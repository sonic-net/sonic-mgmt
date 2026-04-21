# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: in_network
"""

from __future__ import absolute_import, division, print_function

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _is_subnet_of,
    _need_ipaddress,
    ip_network,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.utils import _validate_args


__metaclass__ = type

DOCUMENTATION = """
    name: in_network
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if IP address falls in the network
    description:
        - This plugin checks if the provided IP address belongs to the provided network
    options:
        ip:
            description:
            - A string that represents an IP address
            - 'For example: C(10.1.1.1)'
            type: str
            required: True
        network:
            description:
            - A string that represents the network address in CIDR form
            - 'For example: C(10.0.0.0/8)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

#### Simple examples

- name: Check if 10.1.1.1 is in 10.0.0.0/8
  ansible.builtin.set_fact:
    data: "{{ '10.1.1.1' is ansible.utils.in_network '10.0.0.0/8' }}"

# TASK [Check if 10.1.1.1 is in 10.0.0.0/8] ***********************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 10.1.1.1 is not in 192.168.1.0/24
  ansible.builtin.set_fact:
    data: "{{ '10.1.1.1' is not ansible.utils.in_network '192.168.1.0/24' }}"

# TASK [Check if 10.1.1.1 is not in 192.168.1.0/24] ****************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 2001:db8:a::123 is in 2001:db8:a::/64
  ansible.builtin.set_fact:
    data: "{{ '2001:db8:a::123' is ansible.utils.in_network '2001:db8:a::/64' }}"

# TASK [Check if 2001:db8:a::123 is in 2001:db8:a::/64] ****************************
# task path: /home/prsahoo/playbooks/collections/localhost_test/utils_in_network.yml:16
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 2001:db8:a::123 is not in 10.0.0.0/8
  ansible.builtin.set_fact:
    data: "{{ '2001:db8:a::123' is not ansible.utils.in_network '10.0.0.0/8' }}"

# TASK [Check if 2001:db8:a::123 is not in 10.0.0.0/8] *********************************
# task path: /home/prsahoo/playbooks/collections/localhost_test/utils_in_network.yml:20
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
def _in_network(ip, network):
    """Test if an address or network is in a network"""

    params = {"ip": ip, "network": network}
    _validate_args("in_network", DOCUMENTATION, params)

    try:
        return _is_subnet_of(ip_network(ip), ip_network(network))
    except Exception:
        return False


class TestModule(object):
    """network jinja test"""

    test_map = {"in_network": _in_network}

    def tests(self):
        return self.test_map
