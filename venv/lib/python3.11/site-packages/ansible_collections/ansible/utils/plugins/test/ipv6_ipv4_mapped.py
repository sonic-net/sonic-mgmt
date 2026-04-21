# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: ipv6_ipv4_mapped
"""

from __future__ import absolute_import, division, print_function

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
    _validate_args,
    ip_address,
)


__metaclass__ = type

DOCUMENTATION = """
    name: ipv6_ipv4_mapped
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if something appears to be a mapped IPv6 to IPv4 mapped address
    description:
        - This plugin checks if the provided value is a valid IPv4-mapped IPv6 address
    options:
        ip:
            description:
            - A string that represents the value against which the test is going to be performed
            - 'For example: C(::FFFF:10.1.1.1), C(::AAAA:10.1.1.1), or C("helloworld")'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

#### Simple examples

- name: Check if ::FFFF:10.1.1.1 is a valid IPv4-mapped IPv6 address
  ansible.builtin.set_fact:
    data: "{{ '::FFFF:10.1.1.1' is ansible.utils.ipv6_ipv4_mapped }}"

# TASK [Check if ::FFFF:10.1.1.1 is a valid IPv4-mapped IPv6 address] *************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if ::AAAA:10.1.1.1 is not a valid IPv4-mapped IPv6 address
  ansible.builtin.set_fact:
    data: "{{ '::AAAA:10.1.1.1' is not ansible.utils.ipv6_ipv4_mapped }}"

# TASK [Check if ::AAAA:10.1.1.1 is not a valid IPv4-mapped IPv6 address] ******************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if helloworld is not a valid IPv4-mapped IPv6 address
  ansible.builtin.set_fact:
    data: "{{ 'helloworld' is not ansible.utils.ipv6_ipv4_mapped }}"

# TASK [Check if helloworld is not a valid IPv4-mapped IPv6 address] ***********************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }
"""

RETURN = """
  data:
    description:
      - If jinja test satisfies plugin expression C(true)
      - If jinja test does not satisfy plugin expression C(false)
"""


@_need_ipaddress
def _ipv6_ipv4_mapped(ip):
    """Test if something appears to be a mapped IPv6 to IPv4 mapped address"""

    params = {"ip": ip}
    _validate_args("ipv6_ipv4_mapped", DOCUMENTATION, params)

    try:
        if ip_address(ip).ipv4_mapped is None:
            return False
        return True
    except Exception:
        return False


class TestModule(object):
    """network jinja test"""

    test_map = {"ipv6_ipv4_mapped": _ipv6_ipv4_mapped}

    def tests(self):
        return self.test_map
