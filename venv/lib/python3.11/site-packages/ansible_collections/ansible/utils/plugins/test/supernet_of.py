# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: supernet_of
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
    name: supernet_of
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if a network is a supernet of another network
    description:
        - This plugin checks if the first network is a supernet of the second network amongst the provided network addresses
    options:
        network_a:
            description:
            - A string that represents the first network address
            - 'For example: C(10.1.1.0/24)'
            type: str
            required: True
        network_b:
            description:
            - A string that represents the second network address
            - 'For example: C(10.0.0.0/8)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

- name: Check if 10.0.0.0/8 is a supernet of 10.1.1.0/24
  ansible.builtin.set_fact:
    data: "{{ '10.0.0.0/8' is ansible.utils.supernet_of '10.1.1.0/24' }}"

# TASK [Check if 10.0.0.0/8 is a supernet of 10.1.1.0/24] ************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 10.0.0.0/8 is not a supernet of 192.168.1.0/24
  ansible.builtin.set_fact:
    data: "{{ '10.0.0.0/8' is not ansible.utils.supernet_of '192.168.1.0/24' }}"

# TASK [Check if 10.0.0.0/8 is not a supernet of 192.168.1.0/24] *****************
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
def _supernet_of(network_a, network_b):
    """Test if an network is a supernet of another network"""

    params = {"network_a": network_a, "network_b": network_b}
    _validate_args("supernet_of", DOCUMENTATION, params)

    try:
        return _is_subnet_of(ip_network(network_b), ip_network(network_a))
    except Exception:
        return False


class TestModule(object):
    """network jinja test"""

    test_map = {"supernet_of": _supernet_of}

    def tests(self):
        return self.test_map
