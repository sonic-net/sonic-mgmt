# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Test plugin file for netaddr tests: mac
"""

from __future__ import absolute_import, division, print_function

import re

from ansible_collections.ansible.utils.plugins.plugin_utils.base.utils import _validate_args


__metaclass__ = type

DOCUMENTATION = """
    name: mac
    author: Priyam Sahoo (@priyamsahoo)
    version_added: "2.2.0"
    short_description: Test if something appears to be a valid MAC address
    description:
        - This plugin checks if the provided value is a valid MAC address that follows the industry level standards
    options:
        mac:
            description:
            - A string that represents the value against which the test is going to be performed
            - 'For example: C(02:16:3e:e4:16:f3), C(02-16-3e-e4-16-f3), C(0216.3ee4.16f3), or C(02163ee416f3)'
            type: str
            required: True
    notes:
"""

EXAMPLES = r"""

- name: Check if 02:16:3e:e4:16:f3 is a valid MAC address
  ansible.builtin.set_fact:
    data: "{{ '02:16:3e:e4:16:f3' is ansible.utils.mac }}"

# TASK [Check if 02:16:3e:e4:16:f3 is a valid MAC address] ********************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 02-16-3e-e4-16-f3 is a valid MAC address
  ansible.builtin.set_fact:
    data: "{{ '02-16-3e-e4-16-f3' is ansible.utils.mac }}"

# TASK [Check if 02-16-3e-e4-16-f3 is a valid MAC address] ********************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 0216.3ee4.16f3 is a valid MAC address
  ansible.builtin.set_fact:
    data: "{{ '0216.3ee4.16f3' is ansible.utils.mac }}"

# TASK [Check if 0216.3ee4.16f3 is a valid MAC address] ***********************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if 02163ee416f3 is a valid MAC address
  ansible.builtin.set_fact:
    data: "{{ '02163ee416f3' is ansible.utils.mac }}"

# TASK [Check if 02163ee416f3 is a valid MAC address] *************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": true
#     },
#     "changed": false
# }

- name: Check if helloworld is not a valid MAC address
  ansible.builtin.set_fact:
    data: "{{ 'helloworld' is not ansible.utils.mac }}"

# TASK [Check if helloworld is not a valid MAC address] ***********************
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


def _mac(mac):
    """Test if something appears to be a valid mac address"""

    params = {"mac": mac}
    _validate_args("mac", DOCUMENTATION, params)

    # IEEE EUI-48 upper and lower, commom unix
    re1 = r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$"
    # Cisco triple hextex
    re2 = r"^([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})$"
    # Bare
    re3 = r"^[0-9a-f]{12}$"
    regex = "(?i){re1}|{re2}|{re3}".format(re1=re1, re2=re2, re3=re3)
    return bool(re.match(regex, mac))


class TestModule(object):
    """network jinja test"""

    test_map = {"mac": _mac}

    def tests(self):
        return self.test_map
