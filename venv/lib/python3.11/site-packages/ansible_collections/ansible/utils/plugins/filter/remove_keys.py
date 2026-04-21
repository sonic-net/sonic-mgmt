#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The remove_keys filter plugin
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    name: remove_keys
    author: Sagar Paul (@KB-perByte)
    version_added: "2.5.0"
    short_description: Remove specific keys from a data recursively.
    description:
        - This plugin removes specific keys from a provided data recursively.
        - Matching parameter defaults to equals unless C(matching_parameter) is explicitly mentioned.
        - Using the parameters below- C(data|ansible.utils.remove_keys(target([....])))
    options:
      data:
        description:
        - This option represents a list of dictionaries or a dictionary with any level of nesting data.
        - For example C(config_data|ansible.utils.remove_keys(target([....]))), in this case C(config_data) represents this option.
        type: raw
        required: True
      target:
        description: Specify the target keys to remove in list format.
        type: list
        elements: str
        required: True
      matching_parameter:
        description: Specify the matching configuration of target keys and data attributes.
        type: str
        choices: ["starts_with","ends_with","regex"]
"""

EXAMPLES = r"""

# example.yaml
# interfaces:
#   - name: eth0
#     enabled: true
#     duplex: auto
#     speed: auto
#     note:
#       - Connected green wire
#   - name: eth1
#     description: Configured by Ansible - Interface 1
#     mtu: 1500
#     speed: auto
#     duplex: auto
#     enabled: true
#     note:
#       - Connected blue wire
#       - Configured by Paul
#     vifs:
#     - vlan_id: 100
#       description: Eth1 - VIF 100
#       mtu: 400
#       enabled: true
#       comment: Needs reconfiguration
#     - vlan_id: 101
#       description: Eth1 - VIF 101
#       enabled: true
#   - name: eth2
#     description: Configured by Ansible - Interface 2 (ADMIN DOWN)
#     mtu: 600
#     enabled: false

# Playbook

- name: remove multiple keys from a provided data
  ansible.builtin.set_fact:
    data: '{{ interfaces }}'
- debug:
    msg: '{{ data|ansible.utils.remove_keys(target=[''note'', ''comment'']) }}'

# Output
# TASK [remove multiple keys from a provided data] ***************************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": [
#             {
#                 "duplex": "auto",
#                 "enabled": true,
#                 "name": "eth0",
#                 "note": [
#                     "Connected green wire"
#                 ],
#                 "speed": "auto"
#             },
#             {
#                 "description": "Configured by Ansible - Interface 1",
#                 "duplex": "auto",
#                 "enabled": true,
#                 "mtu": 1500,
#                 "name": "eth1",
#                 "note": [
#                     "Connected blue wire",
#                     "Configured by Paul"
#                 ],
#                 "speed": "auto",
#                 "vifs": [
#                     {
#                         "comment": "Needs reconfiguration",
#                         "description": "Eth1 - VIF 100",
#                         "enabled": true,
#                         "mtu": 400,
#                         "vlan_id": 100
#                     },
#                     {
#                         "description": "Eth1 - VIF 101",
#                         "enabled": true,
#                         "vlan_id": 101
#                     }
#                 ]
#             },
#             {
#                 "description": "Configured by Ansible - Interface 2 (ADMIN DOWN)",
#                 "enabled": false,
#                 "mtu": 600,
#                 "name": "eth2"
#             }
#         ]
#     },
#     "changed": false
# }
# Read vars_file 'example.yaml'

# TASK [debug] ********************************************
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
#   - name: eth0
#     enabled: true
#     duplex: auto
#     speed: auto
#     note:
#       - Connected green wire
#   - name: eth1
#     description: Configured by Ansible - Interface 1
#     mtu: 1500
#     speed: auto
#     duplex: auto
#     enabled: true
#     note:
#       - Connected blue wire
#       - Configured by Paul
#     vifs:
#     - vlan_id: 100
#       description: Eth1 - VIF 100
#       mtu: 400
#       enabled: true
#       comment: Needs reconfiguration
#     - vlan_id: 101
#       description: Eth1 - VIF 101
#       enabled: true
#   - name: eth2
#     description: Configured by Ansible - Interface 2 (ADMIN DOWN)
#     mtu: 600
#     enabled: false

# Playbook
- name: remove multiple keys from a provided data
  ansible.builtin.set_fact:
    data: '{{ interfaces }}'
- debug:
    msg: >-
      {{ data|ansible.utils.remove_keys(target=['^note$', '^comment'],
      matching_parameter= 'regex') }}

# Output
# TASK [remove multiple keys from a provided data] ***********************
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": [
#             {
#                 "duplex": "auto",
#                 "enabled": true,
#                 "name": "eth0",
#                 "note": [
#                     "Connected green wire"
#                 ],
#                 "speed": "auto"
#             },
#             {
#                 "description": "Configured by Ansible - Interface 1",
#                 "duplex": "auto",
#                 "enabled": true,
#                 "mtu": 1500,
#                 "name": "eth1",
#                 "note": [
#                     "Connected blue wire",
#                     "Configured by Paul"
#                 ],
#                 "speed": "auto",
#                 "vifs": [
#                     {
#                         "comment": "Needs reconfiguration",
#                         "description": "Eth1 - VIF 100",
#                         "enabled": true,
#                         "mtu": 400,
#                         "vlan_id": 100
#                     },
#                     {
#                         "description": "Eth1 - VIF 101",
#                         "enabled": true,
#                         "vlan_id": 101
#                     }
#                 ]
#             },
#             {
#                 "description": "Configured by Ansible - Interface 2 (ADMIN DOWN)",
#                 "enabled": false,
#                 "mtu": 600,
#                 "name": "eth2"
#             }
#         ]
#     },
#     "changed": false
# }
# Read vars_file 'example.yaml'

# TASK [debug] *****************************************
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
from ansible_collections.ansible.utils.plugins.plugin_utils.remove_keys import remove_keys


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment


@pass_environment
def _remove_keys(*args, **kwargs):
    """remove specific keys from a data recursively"""

    keys = ["data", "target", "matching_parameter"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="remove_keys")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return remove_keys(**updated_data)


class FilterModule(object):
    """remove_keys"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"remove_keys": _remove_keys}
