# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
name: nios_next_vlan_id
short_description: Return the next available VLAN ID for a VLAN view/range
version_added: "1.8.0"
description:
  - Uses the Infoblox WAPI API to return the next available VLAN IDs for a given VLAN view/range
requirements:
  - infoblox_client

options:
    parent:
      description: The VLAN view/range to retrieve the VLAN IDs from.
      required: false
      default: default
      type: str
    num:
      description: The number of VLAN IDs to return.
      required: false
      default: 1
      type: int
    exclude:
      description: List of VLAN IDs that need to be excluded from returned VLAN IDs.
      required: false
      type: list
      elements: int
'''

EXAMPLES = """
- name: return the next available VLAN ID from a VLAN view
  ansible.builtin.set_fact:
    networkaddr: "{{ lookup('infoblox.nios_modules.nios_next_vlan_id', parent='vlanview',
                        provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return the next two available VLAN IDs from a VLAN range
  ansible.builtin.set_fact:
    networkaddr: "{{ lookup('infoblox.nios_modules.nios_next_vlan_id', parent='vlanrange', num=2,
                        provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: return the next available VLAN ID, excluding IDs 1-3
  ansible.builtin.set_fact:
    networkaddr: "{{ lookup('infoblox.nios_modules.nios_next_vlan_id', parent='vlanrange', exclude=[1,2,3],
                        provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"
"""

RETURN = """
_list:
  description:
    - The list of next vlan ids available
  returned: always
  type: list
"""

from ansible.plugins.lookup import LookupBase
from ansible.module_utils._text import to_text
from ansible.errors import AnsibleError
from ..module_utils.api import WapiLookup


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        parent_ref = str()
        provider = kwargs.pop('provider', {})
        wapi = WapiLookup(provider)
        num = kwargs.get('num', 1)
        exclude_vlan_id = kwargs.get('exclude', [])
        parent = kwargs.get('parent', 'default')

        try:
            parent_obj_vlanview = wapi.get_object('vlanview', {'name': parent})
            parent_obj_vlanrange = wapi.get_object('vlanrange', {'name': parent})
            if parent_obj_vlanrange:
                parent_ref = parent_obj_vlanrange[0]['_ref']
            elif parent_obj_vlanview:
                parent_ref = parent_obj_vlanview[0]['_ref']
            else:
                raise AnsibleError(message='VLAN View/Range \'%s\' cannot be found.' % parent)

            avail_ids = wapi.call_func('next_available_vlan_id', parent_ref, {'num': num, 'exclude': exclude_vlan_id})
            return [avail_ids['vlan_ids']]

        except Exception as exc:
            raise AnsibleError(to_text(exc))
