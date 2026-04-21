# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: ipv4_netmask
"""

from __future__ import absolute_import, division, print_function

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
    ip_network,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.utils import _validate_args


__metaclass__ = type

DOCUMENTATION = """
    name: ipv4_netmask
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if an address is a valid netmask
    description:
        - This plugin checks if the provided ip address is a valid IPv4 netmask or not
    options:
        mask:
            description:
            - A string that represents the value against which the test is going to be performed
            - 'For example: C(0.1.255.255) or C(255.255.255.0)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

#### Simple examples

- name: Check if 255.255.255.0 is a netmask
  ansible.builtin.set_fact:
    data: "{{ '255.255.255.0' is ansible.utils.ipv4_netmask }}"

# TASK [Check if 255.255.255.0 is a netmask] *******************************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 255.255.255.128 is a netmask
  ansible.builtin.set_fact:
    data: "{{ '255.255.255.128' is ansible.utils.ipv4_netmask }}"

# TASK [Check if 255.255.255.128 is a netmask] *****************************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 255.255.255.127 is not a netmask
  ansible.builtin.set_fact:
    data: "{{ '255.255.255.127' is not ansible.utils.ipv4_netmask }}"

# TASK [Check if 255.255.255.127 is not a netmask] *************************************
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
def _ipv4_netmask(mask):
    """Test for a valid IPv4 netmask"""

    params = {"mask": mask}
    _validate_args("ipv4_netmask", DOCUMENTATION, params)

    try:
        network = ip_network("10.0.0.0/{mask}".format(mask=mask))
        return str(network.netmask) == mask
    except Exception:
        return False


class TestModule(object):
    """network jinja test"""

    test_map = {"ipv4_netmask": _ipv4_netmask}

    def tests(self):
        return self.test_map
