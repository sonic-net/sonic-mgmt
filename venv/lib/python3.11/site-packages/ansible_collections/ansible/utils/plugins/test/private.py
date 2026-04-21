# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: private
"""

from __future__ import absolute_import, division, print_function

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
    ip_address,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.utils import _validate_args


__metaclass__ = type

DOCUMENTATION = """
    name: private
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if an IP address is private
    description:
        - This plugin checks if the provided value is a private IP address
    options:
        ip:
            description:
            - A string that represents the value against which the test is going to be performed
            - 'For example: C(10.1.1.1), C(8.8.8.8), or C(192.168.1.250)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

- name: Check if 10.1.1.1 is a private IP address
  ansible.builtin.set_fact:
    data: "{{ '10.1.1.1' is ansible.utils.private }}"

# TASK [Check if 10.1.1.1 is a private IP address] *******************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 8.8.8.8 is not a private IP address
  ansible.builtin.set_fact:
    data: "{{ '8.8.8.8' is not ansible.utils.private }}"

# TASK [Check if 8.8.8.8 is not a private IP address] ******************************
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
def _private(ip):
    """Test if an IP address is private"""

    params = {"ip": ip}
    _validate_args("private", DOCUMENTATION, params)

    try:
        return ip_address(ip).is_private
    except Exception:
        return False


class TestModule(object):
    """network jinja test"""

    test_map = {"private": _private}

    def tests(self):
        return self.test_map
