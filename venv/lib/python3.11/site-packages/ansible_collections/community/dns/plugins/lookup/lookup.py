# -*- coding: utf-8 -*-

# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
name: lookup
author: Felix Fontein (@felixfontein)
short_description: Look up DNS records
version_added: 2.6.0
requirements:
  - dnspython >= 1.15.0 (maybe older versions also work)
description:
  - Look up DNS records.
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
      - V(message) adds the string V(NXDOMAIN) to RV(_result).
    type: str
    choices:
      - empty
      - fail
      - message
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
- name: Look up A (IPv4) records for example.org
  ansible.builtin.debug:
    msg: "{{ query('community.dns.lookup', 'example.org.') }}"

- name: Look up AAAA (IPv6) records for example.org
  ansible.builtin.debug:
    msg: "{{ query('community.dns.lookup', 'example.org.', type='AAAA' ) }}"
"""

RETURN = r"""
_result:
  description:
    - The records of type O(type) for all queried DNS names.
    - If multiple DNS names are queried in O(_terms), the resulting lists have been concatenated.
  type: list
  elements: str
  sample:
    - 127.0.0.1
"""

import typing as t
from collections.abc import Callable

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
        nxdomain_handling: t.Literal["empty", "fail", "message"],
        target_can_be_relative: bool = True,
        search: bool = True,
    ) -> list[str]:
        def callback() -> list[str]:
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
                return [to_text(data) for data in rrset]
            except dns.resolver.NXDOMAIN:
                if nxdomain_handling == "message":
                    return ["NXDOMAIN"]
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
    ) -> list[str]:
        assert_requirements_present_dnspython("community.dns.lookup", "lookup")

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

        nxdomain_handling: t.Literal["empty", "fail", "message"] = self.get_option(
            "nxdomain_handling"
        )

        search: bool = self.get_option("search")

        server_addresses: list[str] | None = None
        if self.get_option("server"):
            server_addresses = []
            assert_requirements_present_ipaddress("community.dns.lookup", "lookup")
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
