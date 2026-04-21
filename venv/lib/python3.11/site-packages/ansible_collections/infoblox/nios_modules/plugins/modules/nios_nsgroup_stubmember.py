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
module: nios_nsgroup_stubmember
short_description: Configure Infoblox DNS Nameserver Stub Member Groups
extends_documentation_fragment: infoblox.nios_modules.nios
author:
  - Mauricio Teixeira (@badnetmask)
version_added: "1.7.0"
description:
  - Adds and/or removes nameserver groups of type "Stub Member" form Infoblox NIOS servers.
    This module manages NIOS C(nsgroup:stubmember) objects using the Infoblox. WAPI interface over REST.
requirements:
  - infoblox_client
options:
  name:
    description:
      - Specifies the name of the NIOS nameserver group to be managed.
    required: true
    type: str
  stub_members:
    description:
      - Specifies the list of members to be used
    required: true
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Provide the name of the member
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
- name: create infoblox nameserver stub member group
  infoblox.nios_modules.nios_nsgroup_stubmember:
    name: my-stubmember-group
    comment: "this is a stub member nameserver group"
    stub_members:
      - name: member.localdomain
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
from ..module_utils.api import NIOS_NSGROUP_STUBMEMBER
from ..module_utils.api import normalize_ib_spec


def main():
    '''entrypoint for module execution.'''
    argument_spec = dict(
        provider=dict(required=True),
        state=dict(default='present', choices=['present', 'absent']),
    )

    stub_members_spec = dict(
        name=dict(required=True),
    )

    ib_spec = dict(
        name=dict(required=True, ib_req=True),
        stub_members=dict(type='list', elements='dict', required=True, options=stub_members_spec),
        extattrs=dict(type='dict'),
        comment=dict(),
    )

    argument_spec.update(normalize_ib_spec(ib_spec))
    argument_spec.update(WapiModule.provider_spec)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    wapi = WapiModule(module)
    result = wapi.run(NIOS_NSGROUP_STUBMEMBER, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
