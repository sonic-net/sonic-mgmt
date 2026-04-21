# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: reserved
"""

from __future__ import absolute_import, division, print_function

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
    ip_address,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.base.utils import _validate_args


__metaclass__ = type

DOCUMENTATION = """
    name: reserved
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test for a reserved IP address
    description:
        - This plugin checks if the provided value is a reserved IP address
    options:
        ip:
            description:
            - A string that represents the value against which the test is going to be performed
            - 'For example: C(253.0.0.1) or C(128.146.1.7)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

- name: Check if 253.0.0.1 is a reserved IP address
  ansible.builtin.set_fact:
    data: "{{ '253.0.0.1' is ansible.utils.reserved }}"

# TASK [Check if 253.0.0.1 is a reserved IP address] *****************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 128.146.1.7 is not a reserved IP address
  ansible.builtin.set_fact:
    data: "{{ '128.146.1.7' is not ansible.utils.reserved }}"

# TASK [Check if 128.146.1.7 is not a reserved IP address] ***********************
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
def _reserved(ip):
    """Test for a reserved IP address"""

    params = {"ip": ip}
    _validate_args("reserved", DOCUMENTATION, params)

    try:
        return ip_address(ip).is_reserved
    except Exception:
        return False


class TestModule(object):
    """network jinja test"""

    test_map = {"reserved": _reserved}

    def tests(self):
        return self.test_map
