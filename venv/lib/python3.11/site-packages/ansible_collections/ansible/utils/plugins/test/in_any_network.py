# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: in_any_network
"""

from __future__ import absolute_import, division, print_function

from ansible_collections.ansible.utils.plugins.plugin_utils.base.utils import _validate_args
from ansible_collections.ansible.utils.plugins.test.in_network import _in_network


__metaclass__ = type

DOCUMENTATION = """
    name: in_any_network
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if an IP or network falls in any network
    description:
        - This plugin checks if the provided IP or network address belongs to the provided list network addresses
    options:
        ip:
            description:
            - A string that represents an IP address of a host or network
            - 'For example: C(10.1.1.1)'
            type: str
            required: True
        networks:
            description:
            - A list of string and each string represents a network address in CIDR form
            - "For example: C(['10.0.0.0/8', '192.168.1.0/24'])"
            type: list
            required: True
    notes:
"""

EXAMPLES = r"""

#### Simple examples

- name: Set network list
  ansible.builtin.set_fact:
    networks:
      - "10.0.0.0/8"
      - "192.168.1.0/24"

- name: Check if 10.1.1.1 is in the provided network list
  ansible.builtin.set_fact:
    data: "{{ '10.1.1.1' is ansible.utils.in_any_network networks }}"

# TASK [Check if 10.1.1.1 is in the provided network list] **************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Set network list
  ansible.builtin.set_fact:
    networks:
      - "10.0.0.0/8"
      - "192.168.1.0/24"
      - "172.16.0.0/16"

- name: Check if 8.8.8.8 is not in the provided network list
  ansible.builtin.set_fact:
    data: "{{ '8.8.8.8' is not ansible.utils.in_any_network networks }}"

# TASK [Check if 8.8.8.8 is not in the provided network list] ************************
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


def _in_any_network(ip, networks):
    """Test if an IP or network is in any network"""

    params = {"ip": ip, "networks": networks}
    _validate_args("in_any_network", DOCUMENTATION, params)

    bools = [_in_network(ip, network) for network in networks]
    if True in bools:
        return True
    return False


class TestModule(object):
    """network jinja test"""

    test_map = {"in_any_network": _in_any_network}

    def tests(self):
        return self.test_map
