# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
name: reverse_pointer
short_description: Convert an IP address into a DNS name for reverse lookup
version_added: 3.1.0
description:
  - Given an IPv4 or IPv6 address, such as V(192.168.1.2), converts it to a DNS name to use for reverse lookups, such as V(2.1.168.192.in-addr.arpa).
options:
  _input:
    description:
      - The IP address.
    type: string
    required: true
author:
  - Felix Fontein (@felixfontein)
seealso:
  - name: RFC 1035, Section 3.5
    link: https://www.rfc-editor.org/rfc/rfc1035.html#section-3.5
    description: Describes C(in-addr.arpa).
  - name: RFC 3152
    link: https://www.rfc-editor.org/rfc/rfc3152.html
    description: Describes C(ip6.arpa).
"""

EXAMPLES = r"""
- name: Convert IP address to DNS name for reverse lookup
  ansible.builtin.set_fact:
    dns_name: "{{ ip_address | community.dns.reverse_pointer }}"
  # Should result in '2.1.168.192.in-addr.arpa.'
  vars:
    ip_address: 192.168.1.2
"""

RETURN = r"""
_value:
  description: The DNS name.
  type: string
"""


import typing as t
from collections.abc import Callable

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_text
from ansible_collections.community.dns.plugins.plugin_utils.ips import (
    assert_requirements_present,
)


try:
    import ipaddress
except ImportError:  # pragma: no cover
    # handled by assert_requirements_present
    pass  # pragma: no cover


def reverse_pointer(ip: t.Any) -> str:
    assert_requirements_present("community.dns.reverse_pointer", "filter")
    if not isinstance(ip, (str, bytes)):
        raise AnsibleFilterError(
            "Input for community.dns.reverse_pointer must be a string"
        )
    try:
        ipaddr = ipaddress.ip_address(to_text(ip))
    except Exception as e:
        raise AnsibleFilterError(f"Cannot parse IP address: {e}")
    res = ipaddr.reverse_pointer
    if not res.endswith("."):
        res += "."
    else:
        pass  # pragma: no cover
    return res


class FilterModule:
    """Ansible jinja2 filters"""

    def filters(self) -> dict[str, Callable]:
        return {
            "reverse_pointer": reverse_pointer,
        }
