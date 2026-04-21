#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The replace_keys filter plugin
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    name: replace_keys
    author: Sagar Paul (@KB-perByte)
    version_added: "2.5.0"
    short_description: Replaces specific keys with their after value from a data recursively.
    description:
        - This plugin replaces specific keys with their after value from a data recursively.
        - Matching parameter defaults to equals unless C(matching_parameter) is explicitly mentioned.
        - Using the parameters below- C(data|ansible.utils.replace_keys(target([....])))
    options:
      data:
        description:
        - This option represents a list of dictionaries or a dictionary with any level of nesting data.
        - For example C(config_data|ansible.utils.replace_keys(target([....]))), in this case C(config_data) represents this option.
        type: raw
        required: True
      target:
        description: Specify the target keys to replace in list of dictionaries format containing
          before and after key value.
        type: list
        elements: dict
        required: True
        suboptions:
          before:
            description: before attribute key [to change]
            type: str
          after:
            description: after attribute key [change to]
            type: str
      matching_parameter:
        description: Specify the matching configuration of target keys and data attributes.
        type: str
        choices: ["starts_with","ends_with","regex"]
"""

EXAMPLES = r"""
# example.yaml
# interfaces:
#   - interface_name: eth0
#     enabled: true
#     duplex: auto
#     speed: auto
#   - interface_name: eth1
#     description: Configured by Ansible - Interface 1
#     mtu: 1500
#     speed: auto
#     duplex: auto
#     is_enabled: true
#     vifs:
#     - vlan_id: 100
#       description: Eth1 - VIF 100
#       mtu: 400
#       is_enabled: true
#     - vlan_id: 101
#       description: Eth1 - VIF 101
#       is_enabled: true
#   - interface_name: eth2
#     description: Configured by Ansible - Interface 2 (ADMIN DOWN)
#     mtu: 600
#     is_enabled: false

# Playbook
- name: replace keys with specified keys dict/list to dict
  ansible.builtin.set_fact:
    data: '{{ interfaces }}'
- debug:
    msg: >-
      {{ data|ansible.utils.replace_keys(target=[{'before':'interface_name',
      'after':'name'}, {'before':'is_enabled', 'after':'enabled'}]) }}

# Output
# TASK [replace keys with specified keys dict/list to dict] *************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": [
#             {
#                 "duplex": "auto",
#                 "enabled": true,
#                 "interface_name": "eth0",
#                 "speed": "auto"
#             },
#             {
#                 "description": "Configured by Ansible - Interface 1",
#                 "duplex": "auto",
#                 "interface_name": "eth1",
#                 "is_enabled": true,
#                 "mtu": 1500,
#                 "speed": "auto",
#                 "vifs": [
#                     {
#                         "description": "Eth1 - VIF 100",
#                         "is_enabled": true,
#                         "mtu": 400,
#                         "vlan_id": 100
#                     },
#                     {
#                         "description": "Eth1 - VIF 101",
#                         "is_enabled": true,
#                         "vlan_id": 101
#                     }
#                 ]
#             },
#             {
#                 "description": "Configured by Ansible - Interface 2 (ADMIN DOWN)",
#                 "interface_name": "eth2",
#                 "is_enabled": false,
#                 "mtu": 600
#             }
#         ]
#     },
#     "changed": false
# }

# TASK [debug] **********************************************************************
# ok: [localhost] => {
#     "msg": [
#         {
#             "duplex": "auto",
#             "enabled": true,
#             "name": "eth0",
#             "speed": "auto"
#         },
#         {
#             "description": "Configured by Ansible - Interface 1",
#             "duplex": "auto",
#             "enabled": true,
#             "mtu": 1500,
#             "name": "eth1",
#             "speed": "auto",
#             "vifs": [
#                 {
#                     "description": "Eth1 - VIF 100",
#                     "enabled": true,
#                     "mtu": 400,
#                     "vlan_id": 100
#                 },
#                 {
#                     "description": "Eth1 - VIF 101",
#                     "enabled": true,
#                     "vlan_id": 101
#                 }
#             ]
#         },
#         {
#             "description": "Configured by Ansible - Interface 2 (ADMIN DOWN)",
#             "enabled": false,
#             "mtu": 600,
#             "name": "eth2"
#         }
#     ]
# }

# example.yaml
# interfaces:
#   - interface_name: eth0
#     enabled: true
#     duplex: auto
#     speed: auto
#   - interface_name: eth1
#     description: Configured by Ansible - Interface 1
#     mtu: 1500
#     speed: auto
#     duplex: auto
#     is_enabled: true
#     vifs:
#     - vlan_id: 100
#       description: Eth1 - VIF 100
#       mtu: 400
#       is_enabled: true
#     - vlan_id: 101
#       description: Eth1 - VIF 101
#       is_enabled: true
#   - interface_name: eth2
#     description: Configured by Ansible - Interface 2 (ADMIN DOWN)
#     mtu: 600
#     is_enabled: false

# Playbook
- name: replace keys with specified keys dict/list to dict
  ansible.builtin.set_fact:
    data: '{{ interfaces }}'
- debug:
    msg: >-
      {{ data|ansible.utils.replace_keys(target=[{'before':'name',
      'after':'name'}, {'before':'enabled', 'after':'enabled'}],
      matching_parameter= 'ends_with') }}

# Output
# TASK [replace keys with specified keys dict/list to dict] *********************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": [
#             {
#                 "duplex": "auto",
#                 "enabled": true,
#                 "interface_name": "eth0",
#                 "speed": "auto"
#             },
#             {
#                 "description": "Configured by Ansible - Interface 1",
#                 "duplex": "auto",
#                 "interface_name": "eth1",
#                 "is_enabled": true,
#                 "mtu": 1500,
#                 "speed": "auto",
#                 "vifs": [
#                     {
#                         "description": "Eth1 - VIF 100",
#                         "is_enabled": true,
#                         "mtu": 400,
#                         "vlan_id": 100
#                     },
#                     {
#                         "description": "Eth1 - VIF 101",
#                         "is_enabled": true,
#                         "vlan_id": 101
#                     }
#                 ]
#             },
#             {
#                 "description": "Configured by Ansible - Interface 2 (ADMIN DOWN)",
#                 "interface_name": "eth2",
#                 "is_enabled": false,
#                 "mtu": 600
#             }
#         ]
#     },
#     "changed": false
# }

# TASK [debug] ***************************************************************************
# ok: [localhost] => {
#     "msg": [
#         {
#             "duplex": "auto",
#             "enabled": true,
#             "name": "eth0",
#             "speed": "auto"
#         },
#         {
#             "description": "Configured by Ansible - Interface 1",
#             "duplex": "auto",
#             "enabled": true,
#             "mtu": 1500,
#             "name": "eth1",
#             "speed": "auto",
#             "vifs": [
#                 {
#                     "description": "Eth1 - VIF 100",
#                     "enabled": true,
#                     "mtu": 400,
#                     "vlan_id": 100
#                 },
#                 {
#                     "description": "Eth1 - VIF 101",
#                     "enabled": true,
#                     "vlan_id": 101
#                 }
#             ]
#         },
#         {
#             "description": "Configured by Ansible - Interface 2 (ADMIN DOWN)",
#             "enabled": false,
#             "mtu": 600,
#             "name": "eth2"
#         }
#     ]
# }
"""

from ansible.errors import AnsibleFilterError

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.replace_keys import replace_keys


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment


@pass_environment
def _replace_keys(*args, **kwargs):
    """replaces specific keys with their after value from a data recursively"""

    keys = ["data", "target", "matching_parameter"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="replace_keys")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return replace_keys(**updated_data)


class FilterModule(object):
    """replace_keys"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"replace_keys": _replace_keys}
