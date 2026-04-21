# -*- coding: utf-8 -*-

# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
name: lookup_as_dict
author: Felix Fontein (@felixfontein)
short_description: Look up DNS records as dictionaries
version_added: 2.6.0
requirements:
  - dnspython >= 1.15.0 (maybe older versions also work)
description:
  - Look up DNS records and return them as interpreted dictionaries.
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
      - Note that this behavior changed in community.dns 3.0.0. In community.dns 2.x.y, O(search=false) was the only available
        choice.
    type: bool
    default: true
    version_added: 3.0.0
notes:
  - Note that when using this lookup plugin with V(lookup(\)), and the result is a one-element list, Ansible simply returns
    the one element not as a list. Since this behavior is surprising and can cause problems, it is better to use V(query(\))
    instead of V(lookup(\)). See the examples and also R(Forcing lookups to return lists, query) in the Ansible documentation.
"""

EXAMPLES = r"""
- name: Look up A (IPv4) records for example.org as a list of dictionaries
  ansible.builtin.debug:
    msg: "{{ query('community.dns.lookup_as_dict', 'example.org.') }}"

- name: Look up AAAA (IPv6) records for example.org as a list of IPv6 addresses
  ansible.builtin.debug:
    msg: "{{ query('community.dns.lookup_as_dict', 'example.org.', type='AAAA' ) | map(attribute='address') }}"

- name: Look up TXT records for ansible.com as a list of strings
  ansible.builtin.debug:
    msg: "{{ query('community.dns.lookup_as_dict', 'ansible.com.', type='TXT' ) | map(attribute='value') }}"
"""

RETURN = r"""
_result:
  description:
    - The records of type O(type) for all queried DNS names.
    - If multiple DNS names are queried in O(_terms), the resulting lists have been concatenated.
    - Depending on O(type), different fields are returned.
    - For O(type=TXT) and O(type=SPF), also the concatenated value is returned as RV(_result[].value).
  type: list
  elements: dict
  sample:
    - address: 127.0.0.1
  contains:
    address:
      description:
        - A IPv4 respectively IPv6 address.
      type: str
      returned: if O(type=A) or O(type=AAAA)
    algorithm:
      description:
        - The algorithm ID.
      type: int
      returned: if O(type=DNSKEY) or O(type=DS) or O(type=NSEC3) or O(type=NSEC3PARAM) or O(type=RRSIG) or O(type=SSHFP)
    altitude:
      description:
        - The altitude.
      type: float
      returned: if O(type=LOC)
    cert:
      description:
        - The certificate.
      type: str
      returned: if O(type=TLSA)
    cpu:
      description:
        - The CPU.
      type: str
      returned: if O(type=HINFO)
    digest:
      description:
        - The digest.
      type: str
      returned: if O(type=DS)
    digest_type:
      description:
        - The digest's type.
      type: int
      returned: if O(type=DS)
    exchange:
      description:
        - The exchange server.
      type: str
      returned: if O(type=MX)
    expiration:
      description:
        - The expiration Unix timestamp.
      type: int
      returned: if O(type=RRSIG)
    expire:
      description:
        - Number of seconds after which secondary name servers should stop answering request for this zone if the main name
          server does not respond.
      type: int
      returned: if O(type=SOA)
    fingerprint:
      description:
        - The fingerprint.
      type: str
      returned: if O(type=SSHFP)
    flags:
      description:
        - Flags.
        - This is actually of type C(string) for O(type=NAPTR).
      type: int
      returned: if O(type=CAA) or O(type=DNSKEY) or O(type=NAPTR) or O(type=NSEC3) or O(type=NSEC3PARAM)
    fp_type:
      description:
        - The fingerprint's type.
      type: int
      returned: if O(type=SSHFP)
    horizontal_precision:
      description:
        - The horizontal precision of the location.
      type: float
      returned: if O(type=LOC)
    inception:
      description:
        - The inception Unix timestamp.
      type: int
      returned: if O(type=RRSIG)
    iterations:
      description:
        - The number of iterations.
      type: int
      returned: if O(type=NSEC3) or O(type=NSEC3PARAM)
    key:
      description:
        - The key.
      type: str
      returned: if O(type=DNSKEY)
    key_tag:
      description:
        - The key's tag.
      type: int
      returned: if O(type=DS) or O(type=RRSIG)
    labels:
      description:
        - The labels.
      type: int
      returned: if O(type=RRSIG)
    latitude:
      description:
        - The location's latitude.
      type: list
      elements: int
      returned: if O(type=LOC)
    longitude:
      description:
        - The location's longitude.
      type: list
      elements: int
      returned: if O(type=LOC)
    mbox:
      description:
        - The mbox.
      type: str
      returned: if O(type=RP)
    minimum:
      description:
        - Used to calculate the TTL for purposes of negative caching.
      type: int
      returned: if O(type=SOA)
    mname:
      description:
        - Primary main name server for this zone.
      type: str
      returned: if O(type=SOA)
    mtype:
      description:
        - The mtype.
      type: int
      returned: if O(type=TLSA)
    next:
      description:
        - The next value.
      type: str
      returned: if O(type=NSEC) or O(type=NSEC3)
    order:
      description:
        - The order value.
      type: int
      returned: if O(type=NAPTR)
    original_ttl:
      description:
        - The original TTL.
      type: int
      returned: if O(type=RRSIG)
    os:
      description:
        - The operating system.
      type: str
      returned: if O(type=HINFO)
    params:
      description:
        - The parameters. See L(RFC 9460, https://datatracker.ietf.org/doc/rfc9460/?include_text=1) for details.
      type: dict
      returned: if O(type=HTTPS) or O(type=SVCB)
      contains:
        mandatory:
          description:
            - Keys of parameters that are considered mandatory.
          type: list
          elements: str
        alpn:
          description:
            - List of Base64-encoded ALPN IDs.
          type: list
          elements: str
        no-default-alpn:
          description:
            - The value will always be V(null) if this key is present.
          type: raw
        port:
          description:
            - A port.
          type: int
        ipv4hint:
          description:
            - A list of IPv4 addresses.
          type: list
          elements: str
        ech:
          description:
            - A Base64-encoded ECH (Encrypted Client Hello) key.
          type: raw
        ipv6hint:
          description:
            - A list of IPv6 addresses.
          type: list
          elements: str
        ohttp:
          description:
            - The value will always be V(null) if this key is present.
          type: raw
    port:
      description:
        - The port.
      type: int
      returned: if O(type=SRV)
    preference:
      description:
        - The preference value for this record.
      type: int
      returned: if O(type=MX) or O(type=NAPTR)
    priority:
      description:
        - The priority value for this record.
      type: int
      returned: if O(type=HTTPS), O(type=SRV), or O(type=SVCB)
    protocol:
      description:
        - The protocol.
      type: int
      returned: if O(type=DNSKEY)
    refresh:
      description:
        - Number of seconds after which secondary name servers should query the main name server for the SOA record to detect
          zone changes.
      type: int
      returned: if O(type=SOA)
    regexp:
      description:
        - A regular expression.
      type: str
      returned: if O(type=NAPTR)
    replacement:
      description:
        - The replacement.
      type: str
      returned: if O(type=NAPTR)
    retry:
      description:
        - Number of seconds after which secondary name servers should retry to request the serial number from the main name
          server if the main name server does not respond.
      type: int
      returned: if O(type=SOA)
    rname:
      description:
        - E-mail address of the administrator responsible for this zone.
      type: str
      returned: if O(type=SOA)
    salt:
      description:
        - The salt.
      type: str
      returned: if O(type=NSEC3) or O(type=NSEC3PARAM)
    selector:
      description:
        - The selector.
      type: int
      returned: if O(type=TLSA)
    serial:
      description:
        - Serial number for this zone.
      type: int
      returned: if O(type=SOA)
    service:
      description:
        - The service.
      type: str
      returned: if O(type=NAPTR)
    signature:
      description:
        - The signature.
      type: str
      returned: if O(type=RRSIG)
    signer:
      description:
        - The signer.
      type: str
      returned: if O(type=RRSIG)
    size:
      description:
        - The size of the location.
      type: float
      returned: if O(type=LOC)
    strings:
      description:
        - List of strings for this record.
        - See RV(_result[].value) for the concatenated result.
      type: list
      elements: str
      returned: if O(type=SPF) or O(type=TXT)
    tag:
      description:
        - The tag.
      type: str
      returned: if O(type=CAA)
    target:
      description:
        - The target.
      type: str
      returned: if O(type=CNAME), O(type=DNAME), O(type=HTTPS), O(type=NS), O(type=PTR), O(type=SRV), or O(type=SVCB)
    txt:
      description:
        - The TXT value.
      type: str
      returned: if O(type=RP)
    type_covered:
      description:
        - The type covered.
      type: str
      returned: if O(type=RRSIG)
    usage:
      description:
        - The usage flag.
      type: int
      returned: if O(type=TLSA)
    value:
      description:
        - The value.
        - For O(type=SPF) or O(type=TXT), this is the concatenation of RV(_result[].strings).
      type: str
      returned: if O(type=CAA) or O(type=SPF) or O(type=TXT)
    vertical_precision:
      description:
        - The vertical precision of the location.
      type: float
      returned: if O(type=LOC)
    weight:
      description:
        - The service's weight.
      type: int
      returned: if O(type=SRV)
    windows:
      description:
        - The windows.
      type: str
      returned: if O(type=NSEC) or O(type=NSEC3)
"""

import typing as t
from collections.abc import Callable

from ansible.errors import AnsibleLookupError
from ansible.module_utils.common.text.converters import to_text
from ansible.plugins.lookup import LookupBase
from ansible_collections.community.dns.plugins.module_utils.dnspython_records import (
    NAME_TO_RDTYPE,
    NAME_TO_REQUIRED_VERSION,
    convert_rdata_to_dict,
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
    import dns.resolver
    from dns.rdatatype import RdataType
    from dns.resolver import NXDOMAIN
except ImportError:
    # handled by assert_requirements_present_dnspython
    pass
else:
    RdataType = int  # type: ignore  # noqa: F811


class LookupModule(LookupBase):
    @staticmethod
    def _resolve(
        resolver: SimpleResolver,
        name: str,
        rdtype: RdataType,
        server_addresses: list[str] | None,
        nxdomain_handling: t.Literal["empty", "fail"],
        target_can_be_relative: bool = True,
        search: bool = True,
    ) -> list[dict[str, t.Any]]:
        def callback() -> list[dict[str, t.Any]]:
            try:
                rrset = resolver.resolve(
                    name,
                    rdtype=rdtype,
                    server_addresses=server_addresses,
                    nxdomain_is_empty=nxdomain_handling == "empty",
                    target_can_be_relative=target_can_be_relative,
                    search=search,
                )
                if not rrset:
                    return []
                return [convert_rdata_to_dict(data) for data in rrset]
            except dns.resolver.NXDOMAIN:
                raise AnsibleLookupError(f"Got NXDOMAIN when querying {name}")

        return guarded_run(
            callback,
            error_class=AnsibleLookupError,
            server=name,
        )

    @staticmethod
    def _get_resolver(resolver: SimpleResolver, server: str) -> Callable[[], list[str]]:
        def f():
            try:
                return resolver.resolve_addresses(server)
            except NXDOMAIN as exc:
                raise AnsibleLookupError(f"Nameserver {server} does not exist ({exc})")

        return f

    def run(
        self, terms: list[t.Any], variables: t.Any | None = None, **kwargs: t.Any
    ) -> list[dict[str, t.Any]]:
        assert_requirements_present_dnspython("community.dns.lookup", "lookup_as_dict")

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
                "community.dns.lookup", "lookup_as_dict"
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
            result.extend(
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
