# -*- coding: utf-8 -*-

# Copyright (c) 2023-2025, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
name: lookup_rfc8427
author:
  - Felix Fontein (@felixfontein)
  - Vasiliy Kiryanov (@vasiliyk)
short_description: Look up DNS records and return RFC 8427 JSON format
version_added: 3.4.0
requirements:
  - dnspython >= 1.15.0 (maybe older versions also work)
description:
  - Look up DNS records and return them in L(RFC 8427 DNS message JSON format, https://www.rfc-editor.org/rfc/rfc8427.html).
  - RFC 8427 defines a standardized format for representing DNS messages in JSON.
options:
  _terms:
    description:
      - Domain name(s) to query.
    type: list
    elements: str
    required: true
  type:
    description:
      - The record type to retrieve.
      - Support for V(HTTPS) and V(SVCB) has been added in community.dns 3.4.0.
    type: str
    default: A
    choices:
      - A
      - AAAA
      - CAA
      - CNAME
      - DNAME
      - DNSKEY
      - DS
      - HINFO
      - HTTPS
      - LOC
      - MX
      - NAPTR
      - NS
      - NSEC
      - NSEC3
      - NSEC3PARAM
      - PTR
      - RP
      - RRSIG
      - SOA
      - SPF
      - SRV
      - SSHFP
      - SVCB
      - TLSA
      - TXT
  query_retry:
    description:
      - Number of retries for DNS query timeouts.
    type: int
    default: 3
  query_timeout:
    description:
      - Timeout per DNS query in seconds.
    type: float
    default: 10
  server:
    description:
      - The DNS server(s) to use to look up the result. Must be a list of one or more IP addresses.
      - By default, the system's standard resolver is used.
    type: list
    elements: str
  servfail_retries:
    description:
      - How often to retry on SERVFAIL errors.
    type: int
    default: 0
  nxdomain_handling:
    description:
      - How to handle NXDOMAIN errors. These appear if an unknown domain name is queried.
      - V(empty) (default) returns an empty result for that domain name. This means that for the corresponding domain name,
        nothing is added to RV(_result).
      - V(fail) makes the lookup fail.
    type: str
    choices:
      - empty
      - fail
    default: empty
  search:
    description:
      - If V(false), the input is assumed to be an absolute domain name.
      - If V(true), the input is assumed to be a relative domain name if it does not end with C(.), the search list configured
        in the system's resolver configuration will be used for relative names, and the resolver's domain may be added to
        relative names.
    type: bool
    default: true
notes:
  - This plugin returns DNS messages in RFC 8427 JSON format, which includes C(Header), C(Question), C(Answer), C(Authority), and C(Additional) sections.
  - Note that when using this lookup plugin with V(lookup(\)), and the result is a one-element list, Ansible simply returns
    the one element not as a list. Since this behavior is surprising and can cause problems, it is better to use V(query(\))
    instead of V(lookup(\)). See the examples and also R(Forcing lookups to return lists, query) in the Ansible documentation.
"""

EXAMPLES = r"""
- name: Look up A (IPv4) records for example.org in RFC 8427 JSON format
  ansible.builtin.debug:
    msg: "{{ query('community.dns.lookup_rfc8427', 'example.org.') }}"

- name: Look up AAAA (IPv6) records for example.org in RFC 8427 JSON format
  ansible.builtin.debug:
    msg: "{{ query('community.dns.lookup_rfc8427', 'example.org.', type='AAAA' ) }}"

- name: Get complete DNS message for MX records
  ansible.builtin.debug:
    msg: "{{ query('community.dns.lookup_rfc8427', 'example.org.', type='MX' ) }}"
"""

RETURN = r"""
_result:
  description:
    - DNS messages in RFC 8427 JSON format for all queried DNS names.
    - Every element in O(_terms) corresponds to one element in this list.
  type: list
  elements: dict
  sample:
    - Header:
        ID: 12345
        QR: true
        Opcode: 0
        AA: false
        TC: false
        RD: true
        RA: true
        AD: false
        CD: false
        Rcode: 0
        QDCOUNT: 1
        ANCOUNT: 1
        NSCOUNT: 0
        ARCOUNT: 0
      Question:
        - name: example.org.
          type: 1
          class: 1
      Answer:
        - name: example.org.
          type: 1
          class: 1
          TTL: 3600
          data: 93.184.216.34
      Authority: []
      Additional: []
"""

import typing as t

from ansible.errors import AnsibleLookupError
from ansible.module_utils.common.text.converters import to_text
from ansible.plugins.lookup import LookupBase
from ansible_collections.community.dns.plugins.module_utils.dnspython_records import (
    NAME_TO_RDTYPE,
    NAME_TO_REQUIRED_VERSION,
)
from ansible_collections.community.dns.plugins.module_utils.ips import is_ip_address
from ansible_collections.community.dns.plugins.module_utils.resolver import (
    SimpleResolver,
)
from ansible_collections.community.dns.plugins.plugin_utils.ips import (
    assert_requirements_present as assert_requirements_present_ipaddress,
)
from ansible_collections.community.dns.plugins.plugin_utils.resolver import (
    assert_requirements_present as assert_requirements_present_dnspython,
)
from ansible_collections.community.dns.plugins.plugin_utils.resolver import (
    guarded_run,
)

try:
    import dns.flags
    import dns.message
    import dns.query
    import dns.rcode
    import dns.resolver
    from dns.rdatatype import RdataType
    from dns.resolver import NXDOMAIN
except ImportError:
    # handled by assert_requirements_present_dnspython
    pass


class LookupModule(LookupBase):
    @staticmethod
    def _convert_rrset_to_rfc8427(
        rrset: dns.rrset.RRset | None,
    ) -> list[dict[str, object]]:
        """Convert a DNS RRset to RFC 8427 format."""
        if not rrset:
            return []

        records = []
        for rdata in rrset:
            record = {
                "name": str(rrset.name).rstrip("."),  # RFC 8427: no trailing dot
                "type": int(rrset.rdtype),
                "class": dns.rdataclass.to_text(rrset.rdclass),
                "ttl": rrset.ttl,
                "data": str(rdata),
            }
            # For MX and similar, parse data as object if needed
            if rrset.rdtype == dns.rdatatype.MX:
                preference, exchange = str(rdata).split(" ", 1)
                record["data"] = {
                    "preference": int(preference),
                    "exchange": exchange.rstrip("."),
                }
            records.append(record)
        return records

    @staticmethod
    def _convert_message_to_rfc8427(
        message: dns.message.Message, question_name: str, question_type: int
    ) -> dict[str, object]:
        """Convert a DNS message to RFC 8427 JSON format."""

        def rrsets_to_records(rrsets: list[dns.rrset.RRset]) -> list[dict[str, object]]:
            records: list[dict[str, object]] = []
            for rrset in rrsets:
                records.extend(LookupModule._convert_rrset_to_rfc8427(rrset))
            return records

        # RFC 8427 header fields
        header = {
            "id": message.id,
            "flags": [
                f for f in dns.flags.to_text(message.flags).split() if f
            ],  # list of flag strings
            "rcode": dns.rcode.to_text(message.rcode()),
            "question_count": len(message.question),
            "answer_count": len(message.answer),
            "authority_count": len(message.authority),
            "additional_count": len(message.additional),
        }

        # RFC 8427 Question section
        question = [
            {
                "name": question_name.rstrip("."),
                "type": question_type,
                "class": dns.rdataclass.to_text(dns.rdataclass.IN),
            }
        ]

        result: dict[str, object] = {
            "Header": header,
            "Question": question,
            "Answer": rrsets_to_records(message.answer),
            "Authority": rrsets_to_records(message.authority),
            "Additional": rrsets_to_records(message.additional),
        }
        return result

    @staticmethod
    def _resolve(
        resolver: SimpleResolver,
        name: str,
        rdtype: RdataType,
        server_addresses: list[str] | None,
        nxdomain_handling: t.Literal["empty", "fail"],
        target_can_be_relative: bool = True,
        search: bool = True,
    ) -> dict[str, t.Any]:
        def callback() -> dict[str, t.Any]:
            try:
                rrset = resolver.resolve(
                    name,
                    rdtype=rdtype,
                    server_addresses=server_addresses,
                    nxdomain_is_empty=nxdomain_handling == "empty",
                    target_can_be_relative=target_can_be_relative,
                    search=search,
                )
                # Create a response message and append the answer
                query = dns.message.make_query(name, rdtype)
                response_msg = dns.message.make_response(query)
                if rrset:
                    response_msg.answer.append(rrset)
                return LookupModule._convert_message_to_rfc8427(
                    response_msg, name, int(rdtype)
                )
            except dns.resolver.NXDOMAIN:
                raise AnsibleLookupError(f"Got NXDOMAIN when querying {name}")

        return guarded_run(
            callback,
            error_class=AnsibleLookupError,
            server=name,
        )

    @staticmethod
    def _get_resolver(
        resolver: SimpleResolver, server: str
    ) -> t.Callable[[], list[str]]:
        def f():
            try:
                return resolver.resolve_addresses(server)
            except NXDOMAIN as exc:
                raise AnsibleLookupError(f"Nameserver {server} does not exist ({exc})")

        return f

    def run(
        self, terms: list[t.Any], variables: t.Any | None = None, **kwargs: t.Any
    ) -> list[dict[str, t.Any]]:
        assert_requirements_present_dnspython("community.dns.lookup_rfc8427", "lookup")

        self.set_options(var_options=variables, direct=kwargs)

        resolver = SimpleResolver(
            timeout=self.get_option("query_timeout"),
            timeout_retries=self.get_option("query_retry"),
            servfail_retries=self.get_option("servfail_retries"),
        )

        record_type = self.get_option("type")
        if record_type not in NAME_TO_RDTYPE:
            min_version = NAME_TO_REQUIRED_VERSION[record_type]
            raise AnsibleLookupError(
                f"Your dnspython version does not support {record_type} records. You need version {min_version} or newer."
            )
        rdtype = NAME_TO_RDTYPE[record_type]

        nxdomain_handling: t.Literal["empty", "fail"] = self.get_option(
            "nxdomain_handling"
        )

        search: bool = self.get_option("search")

        server_addresses: list[str] | None = None
        if self.get_option("server"):
            server_addresses = []
            assert_requirements_present_ipaddress(
                "community.dns.lookup_rfc8427", "lookup"
            )
            servers: list[str] = self.get_option("server")
            for server in servers:
                if is_ip_address(server):
                    server_addresses.append(server)
                    continue
                server_addresses.extend(
                    guarded_run(
                        self._get_resolver(resolver, server),
                        error_class=AnsibleLookupError,
                        server=server,
                    )
                )

        result = []
        for name in terms:
            result.append(
                self._resolve(
                    resolver,
                    to_text(name),
                    rdtype,
                    server_addresses,
                    nxdomain_handling,
                    target_can_be_relative=search,
                    search=search,
                )
            )
        return result
