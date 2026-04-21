# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: ipv4
"""

from __future__ import absolute_import, division, print_function

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
    _validate_args,
    ip_network,
)


__metaclass__ = type

DOCUMENTATION = """
    name: ipv4
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if something is an IPv4 address or network
    description:
        - This plugin checks if the provided value is a valid host or network IP address with IPv4 addressing scheme
    options:
        ip:
            description:
            - A string that represents the value against which the test is going to be performed
            - 'For example: C(10.1.1.1), C(10.0.0.0/8), or C(fe80::216:3eff:fee4:16f3)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

#### Simple examples

- name: Check if 10.0.0.0/8 is a valid IPv4 address
  ansible.builtin.set_fact:
    data: "{{ '10.0.0.0/8' is ansible.utils.ipv4 }}"

# TASK [Check if 10.0.0.0/8 is a valid IPv4 address] ***************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 192.168.1.250 is a valid IPv4 address
  ansible.builtin.set_fact:
    data: "{{ '192.168.1.250' is ansible.utils.ipv4 }}"

# TASK [Check if 192.168.1.250 is a valid IPv4 address] ********************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if fe80::216:3eff:fee4:16f3 is not a valid IPv4 address
  ansible.builtin.set_fact:
    data: "{{ 'fe80::216:3eff:fee4:16f3' is not ansible.utils.ipv4 }}"

# TASK [Check if fe80::216:3eff:fee4:16f3 is not a valid IPv4 address] *********
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
def _ipv4(ip):
    """Test if something in an IPv4 address or network"""

    params = {"ip": ip}
    _validate_args("ipv4", DOCUMENTATION, params)

    try:
        return ip_network(ip).version == 4
    except Exception:
        return False


class TestModule(object):
    """network jinja test"""

    test_map = {"ipv4": _ipv4}

    def tests(self):
        return self.test_map
