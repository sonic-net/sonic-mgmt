#!/usr/bin/python
# Copyright © 2020 Infoblox Inc
# -*- coding: utf-8 -*-
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: nios_nsgroup_delegation
short_description: Configure Infoblox DNS Nameserver Delegation Groups
extends_documentation_fragment: infoblox.nios_modules.nios
author:
  - Mauricio Teixeira (@badnetmask)
version_added: "1.7.0"
description:
  - Adds and/or removes nameserver groups of type "Delegation" form Infoblox NIOS servers.
    This module manages NIOS C(nsgroup:delegation) objects using the Infoblox. WAPI interface over REST.
requirements:
  - infoblox_client
options:
  name:
    description:
      - Specifies the name of the NIOS nameserver group to be managed.
    required: true
    type: str
  delegate_to:
    description:
      - Specifies the list of name servers to be used
    required: true
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Provide the name of the server
        required: true
        type: str
      address:
        description:
          - Provide the IP address of the server
        required: true
        type: str
  extattrs:
    description:
      - Allows for the configuration of Extensible Attributes on the
        instance of the object.  This argument accepts a set of key / value
        pairs for configuration.
    required: false
    type: dict
  comment:
    description:
      - Configures a text string comment to be associated with the instance
        of this object.  The provided text string will be configured on the
        object instance.
    required: false
    type: str
  state:
    description:
      - Configures the intended state of the instance of the object on
        the NIOS server.  When this value is set to C(present), the object
        is configured on the device and when this value is set to C(absent)
        the value is removed (if necessary) from the device.
    choices: [present, absent]
    default: present
    type: str
'''

EXAMPLES = '''
- name: create infoblox nameserver delegation group
  infoblox.nios_modules.nios_nsgroup_delegation:
    name: my-delegation-group
    comment: "this is a delegation nameserver group"
    delegate_to:
      - name: first
        address: 192.168.0.10
      - name: second
        address: 192.168.0.20
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
from ..module_utils.api import NIOS_NSGROUP_DELEGATION
from ..module_utils.api import normalize_ib_spec


def main():
    '''entrypoint for module execution.'''
    argument_spec = dict(
        provider=dict(required=True),
        state=dict(default='present', choices=['present', 'absent']),
    )

    delegate_to_spec = dict(
        name=dict(required=True),
        address=dict(required=True)
    )

    ib_spec = dict(
        name=dict(required=True, ib_req=True),
        delegate_to=dict(type='list', elements='dict', required=True, options=delegate_to_spec),
        extattrs=dict(type='dict'),
        comment=dict(),
    )

    argument_spec.update(normalize_ib_spec(ib_spec))
    argument_spec.update(WapiModule.provider_spec)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    wapi = WapiModule(module)
    result = wapi.run(NIOS_NSGROUP_DELEGATION, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
