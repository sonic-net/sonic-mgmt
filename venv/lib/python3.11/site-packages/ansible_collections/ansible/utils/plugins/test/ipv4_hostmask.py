# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: ipv4_hostmask
"""

from __future__ import absolute_import, division, print_function

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
    ip_network,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.utils import _validate_args


__metaclass__ = type

DOCUMENTATION = """
    name: ipv4_hostmask
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if an address is a valid hostmask
    description:
        - This plugin checks if the provided ip address is a IPv4 hostmask or not
    options:
        ip:
            description:
            - A string that represents the value against which the test is going to be performed
            - 'For example: C(0.1.255.255) or C(255.255.255.0)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

#### Simple examples

- name: Check if 0.0.0.255 is a hostmask
  ansible.builtin.set_fact:
    data: "{{ '0.0.0.255' is ansible.utils.ipv4_hostmask }}"

# TASK [Check if 0.0.0.255 is a hostmask] ***********************************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 255.255.255.0 is not a hostmask
  ansible.builtin.set_fact:
    data: "{{ '255.255.255.0' is not ansible.utils.ipv4_hostmask }}"

# TASK [Check if 255.255.255.0 is a hostmask] *********************************
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
def _ipv4_hostmask(ip):
    """Test if an address is a hostmask"""

    params = {"ip": ip}
    _validate_args("ipv4_hostmask", DOCUMENTATION, params)

    try:
        ipaddr = ip_network("10.0.0.0/{ip}".format(ip=ip))
        return str(ipaddr.hostmask) == ip
    except Exception:
        return False


class TestModule(object):
    """network jinja test"""

    test_map = {"ipv4_hostmask": _ipv4_hostmask}

    def tests(self):
        return self.test_map
