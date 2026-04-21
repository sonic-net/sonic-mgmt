# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: ipv6_sixtofour
"""

from __future__ import absolute_import, division, print_function

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
    ip_address,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.utils import _validate_args


__metaclass__ = type

DOCUMENTATION = """
    name: ipv6_sixtofour
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if something appears to be a 6to4 address
    description:
        - This plugin checks if the provided value is a valid 6to4 address
    options:
        ip:
            description:
            - A string that represents the value against which the test is going to be performed
            - 'For example: C(2002:c0a8:6301:1::1), C(::AAAA:10.1.1.1), or C("hello_world")'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

#### Simple examples

- name: Check if 2002:c0a8:6301:1::1 is a valid 6to4 address
  ansible.builtin.set_fact:
    data: "{{ '2002:c0a8:6301:1::1' is ansible.utils.ipv6_sixtofour }}"

# TASK [Check if 2002:c0a8:6301:1::1 is a valid 6to4 address] ****************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 2001:c0a8:6301:1::1 is not a valid 6to4 address
  ansible.builtin.set_fact:
    data: "{{ '2001:c0a8:6301:1::1' is not ansible.utils.ipv6_sixtofour }}"

# TASK [Check if 2001:c0a8:6301:1::1 is not a valid 6to4 address] ************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if helloworld is not a valid 6to4 address
  ansible.builtin.set_fact:
    data: "{{ 'helloworld' is not ansible.utils.ipv6_sixtofour }}"

# TASK [Check if helloworld is not a valid 6to4 address] *********************************
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
def _ipv6_sixtofour(ip):
    """Test if something appears to be a 6to4 address"""

    params = {"ip": ip}
    _validate_args("ipv6_sixtofour", DOCUMENTATION, params)

    try:
        if ip_address(ip).sixtofour is None:
            return False
        return True
    except Exception:
        return False


class TestModule(object):
    """network jinja test"""

    test_map = {"ipv6_sixtofour": _ipv6_sixtofour}

    def tests(self):
        return self.test_map
