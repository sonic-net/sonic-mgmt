#!/usr/bin/python
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: nios_vlan
author: "Christoph Spatt (@edeka-spatt)"
short_description: Configure Infoblox NIOS VLANs
version_added: "1.8.0"
description:
  - Adds and/or removes instances of vlan  objects from
    Infoblox NIOS servers.  This module manages NIOS C(vlan) objects
    using the Infoblox WAPI interface over REST.
  - Updates instances of vlan object from Infoblox NIOS servers.
requirements:
  - infoblox-client
extends_documentation_fragment: infoblox.nios_modules.nios
notes:
    - This module supports C(check_mode).
options:
  name:
    description:
      - Specifies the vlan name to add or remove from
        the system.
    type: str
    required: true
  id:
    description:
      - Specifies the vlan id to add or remove from
        the system.
    type: int
    required: true
  parent:
    description:
      - Specifies the vlan parent to add or remove from
        the system. Can be either a C(vlanview) or C(vlanrange)
        name. Fetches the required _ref object automatically.
        If not specified defaults to vlan view C(default).
    type: str
    default: default
  comment:
    description:
      - Configures a text string comment to be associated with the instance
        of this object.  The provided text string will be configured on the
        object instance.
    type: str
    default: ''
  contact:
    description:
      - Contact information for person/team managing or using VLAN.
    type: str
    default: ''
  department:
    description:
      - Department where VLAN is used.
    type: str
    default: ''
  description:
    description:
      - Description for the VLAN object, may be potentially used for
        longer VLAN names.
    type: str
    default: ''
  reserved:
    description:
      - When set VLAN can only be assigned to IPAM object manually.
    type: bool
    default: False
  extattrs:
    description:
      - Allows for the configuration of Extensible Attributes on the
        instance of the object.  This argument accepts a set of key / value
        pairs for configuration.
    type: dict
  state:
    description:
      - Configures the intended state of the instance of the object on
        the NIOS server.  When this value is set to C(present), the object
        is configured on the device and when this value is set to C(absent)
        the value is removed (if necessary) from the device.
    type: str
    default: present
    choices:
      - present
      - absent
'''

EXAMPLES = '''
- name: Create a new vlan
  infoblox.nios_modules.nios_vlan:
    name: ansible
    id: 10
    parent: my_vlanview
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Update the comment for a vlan
  infoblox.nios_modules.nios_vlan:
    name: ansible
    id: 10
    parent: my_vlanview
    comment: this is an example comment
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Remove the vlan
  infoblox.nios_modules.nios_vlan:
    name: ansible
    id: 10
    parent: my_vlanview
    state: absent
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Update an existing vlan
  infoblox.nios_modules.nios_vlan:
    name: {new_name: ansible-new, old_name: ansible}
    id: 10
    parent: my_vlanview
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Create vlan with extensible attributes
  infoblox.nios_modules.nios_vlan:
    name: ansible
    id: 11
    parent: my_vlanview
    comment: "this is an example comment"
    contact: "itlab@email.com"
    department: "IT"
    description: "test"
    reserved: True
    extattrs:
      Site: "HQ"
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: Create a new vlan with next available id
  infoblox.nios_modules.nios_vlan:
    name: ansible-vlan
    id: "{{
        lookup('infoblox.nios_modules.nios_next_vlan_id',
          parent='my_vlanrange',
          exclude=[1,2],
          provider=nios_provider)[0]
        }}"
    parent: my_vlanrange
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local
'''

RETURN = ''' # '''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.api import WapiModule
from ..module_utils.api import NIOS_VLAN
from ..module_utils.api import normalize_ib_spec


def main():
    ''' Main entry point for module execution
    '''

    def parent_transform(module):
        parent_ref = str()
        if module.params['parent']:
            parent_obj_vlanview = wapi.get_object('vlanview', {'name': module.params['parent']})
            parent_obj_vlanrange = wapi.get_object('vlanrange', {'name': module.params['parent']})
            if parent_obj_vlanrange:
                parent_ref = parent_obj_vlanrange[0]['_ref']
            elif parent_obj_vlanview:
                parent_ref = parent_obj_vlanview[0]['_ref']
            else:
                module.fail_json(msg='VLAN View/Range \'%s\' cannot be found.' % module.params['parent'])
        return parent_ref

    ib_spec = dict(
        name=dict(required=True, ib_req=True),
        id=dict(type='int', required=True, ib_req=True),
        parent=dict(default='default', transform=parent_transform),
        comment=dict(default=''),
        contact=dict(default=''),
        department=dict(default=''),
        description=dict(default=''),
        reserved=dict(type='bool', default=False),
        extattrs=dict(type='dict'),
    )

    argument_spec = dict(
        provider=dict(required=True),
        state=dict(default='present', choices=['present', 'absent'])
    )

    argument_spec.update(normalize_ib_spec(ib_spec))
    argument_spec.update(WapiModule.provider_spec)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    wapi = WapiModule(module)
    result = wapi.run(NIOS_VLAN, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
