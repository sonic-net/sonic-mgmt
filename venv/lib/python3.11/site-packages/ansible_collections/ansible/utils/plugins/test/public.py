# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: public
"""

from __future__ import absolute_import, division, print_function

from ansible_collections.ansible.utils.plugins.plugin_utils.base.ipaddress_utils import (
    _need_ipaddress,
    _validate_args,
    ip_address,
)


__metaclass__ = type

DOCUMENTATION = """
    name: public
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if an IP address is public
    description:
        - This plugin checks if the provided value is a public IP address
    options:
        ip:
            description:
            - A string that represents the value against which the test is going to be performed
            - 'For example: C(8.8.8.8), C(10.1.1.1), or C(192.168.1.250)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

- name: Check if 8.8.8.8 is a public IP address
  ansible.builtin.set_fact:
    data: "{{ '8.8.8.8' is ansible.utils.public }}"

# TASK [Check if 8.8.8.8 is a public IP address] *********************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 10.1.1.1 is not a public IP address
  ansible.builtin.set_fact:
    data: "{{ '10.1.1.1' is not ansible.utils.public }}"

# TASK [Check if 10.1.1.1 is not a public IP address] ******************************
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
def _public(ip):
    """Test if an IP address is public"""

    params = {"ip": ip}
    _validate_args("public", DOCUMENTATION, params)

    try:
        return ip_address(ip).is_global
    except Exception:
        return False


class TestModule(object):
    """network jinja test"""

    test_map = {"public": _public}

    def tests(self):
        return self.test_map
