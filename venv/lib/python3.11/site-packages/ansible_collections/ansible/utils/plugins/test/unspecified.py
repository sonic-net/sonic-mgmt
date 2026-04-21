# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: unspecified
"""

from __future__ import absolute_import, division, print_function

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
    _validate_args,
    ip_address,
)


__metaclass__ = type

DOCUMENTATION = """
    name: unspecified
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test for an unspecified IP address
    description:
        - This plugin checks if the provided value is an unspecified IP address
    options:
        ip:
            description:
            - A string that represents the value against which the test is going to be performed
            - 'For example: C(0.0.0.0), C(0:0:0:0:0:0:0:0), C(::), or C(::1)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

#### Simple examples

- name: Check if 0.0.0.0 is an unspecified IP address
  ansible.builtin.set_fact:
    data: "{{ '0.0.0.0' is ansible.utils.unspecified }}"

# TASK [Check if 0.0.0.0 is an unspecified IP address] ***************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 0:0:0:0:0:0:0:0 is an unspecified IP address
  ansible.builtin.set_fact:
    data: "{{ '0:0:0:0:0:0:0:0' is ansible.utils.unspecified }}"

# TASK [Check if 0:0:0:0:0:0:0:0 is an unspecified IP address] *******************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if "::" is an unspecified IP address
  ansible.builtin.set_fact:
    data: "{{ '::' is ansible.utils.unspecified }}"

# TASK [Check if "::" is an unspecified IP address] ******************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if ::1 is not an unspecified IP address
  ansible.builtin.set_fact:
    data: "{{ '::1' is not ansible.utils.unspecified }}"

# TASK [Check if ::1 is not an unspecified IP address] ***************************
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
def _unspecified(ip):
    """Test for an unspecified IP address"""

    params = {"ip": ip}
    _validate_args("unspecified", DOCUMENTATION, params)

    try:
        return ip_address(ip).is_unspecified
    except Exception:
        return False


class TestModule(object):
    """network jinja test"""

    test_map = {"unspecified": _unspecified}

    def tests(self):
        return self.test_map
