# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: loopback
"""

from __future__ import absolute_import, division, print_function

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
    _validate_args,
    ip_address,
)


__metaclass__ = type

DOCUMENTATION = """
    name: loopback
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if an IP address is a loopback
    description:
        - This plugin checks if the provided value is a valid loopback IP address
    options:
        ip:
            description:
            - A string that represents the value against which the test is going to be performed
            - 'For example: C(127.0.0.1) or C(2002::c0a8:6301:1)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

- name: Check if 127.10.10.10 is a valid loopback address
  ansible.builtin.set_fact:
    data: "{{ '127.10.10.10' is ansible.utils.loopback }}"

# TASK [Check if 127.10.10.10 is a valid loopback address] *************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 10.1.1.1 is not a valid loopback address
  ansible.builtin.set_fact:
    data: "{{ '10.1.1.1' is not ansible.utils.loopback }}"

# TASK [Check if 10.1.1.1 is not a valid loopback address] *************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if ::1 is a valid loopback address
  ansible.builtin.set_fact:
    data: "{{ '::1' is ansible.utils.loopback }}"

# TASK [Check if ::1 is a valid loopback address] **********************************
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
def _loopback(ip):
    """Test if an IP address is a loopback"""

    params = {"ip": ip}
    _validate_args("loopback", DOCUMENTATION, params)

    try:
        return ip_address(ip).is_loopback
    except Exception:
        return False


class TestModule(object):
    """network jinja test"""

    test_map = {"loopback": _loopback}

    def tests(self):
        return self.test_map
