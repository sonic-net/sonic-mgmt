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
module: nios_nsgroup_forwardingmember
short_description: Configure Infoblox DNS Nameserver Forwarding Member Groups
extends_documentation_fragment: infoblox.nios_modules.nios
author:
  - Mauricio Teixeira (@badnetmask)
version_added: "1.7.0"
description:
  - Adds and/or removes nameserver groups of type "Forwarding Member" from Infoblox NIOS servers.
    This module manages NIOS C(nsgroup:forwardstubserver) objects using the Infoblox. WAPI interface over REST.
requirements:
  - infoblox_client
options:
  name:
    description:
      - Specifies the name of the NIOS nameserver group to be managed.
    required: true
    type: str
  forwarding_servers:
    description:
      - Specifies the list of forwarding member servers to be used
    required: true
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - The name of the forwarding grid member in FQDN format
        required: true
        type: str
      forwarders_only:
        description:
          - Determines if the appliance sends queries to forwarders only, and not to other internal or Internet root servers.
        required: false
        type: bool
        default: false
      use_override_forwarders:
        description:
          - When using c(forward_to) option, and this is set to C(True), only the defined custom forwarders will be used (no recurse to root nameservers).
        required: false
        type: bool
        default: false
      forward_to:
        description:
          - The information for the remote name server to which you want the Infoblox appliance to forward queries for a specified domain name.
        required: false
        type: list
        default: []
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
- name: create infoblox nameserver forwarding member group
  infoblox.nios_modules.nios_nsgroup_forwardingmember:
    name: my-forwardingmember-group
    comment: "this is a forwarding member nameserver group"
    forwarding_servers:
      - name: member.localdomain
    state: present
    provider:
      host: "{{ inventory_hostname_short }}"
      username: admin
      password: admin
  connection: local

- name: create infoblox nameserver forwarding member group with external forwarders
  infoblox.nios_modules.nios_nsgroup_forwardingmember:
    name: my-forwardingmember-group
    comment: "this is a forwarding member nameserver group with external forwarders"
    forwarding_servers:
      - name: member.localdomain
        use_override_forwarders: true
        forward_to:
          - name: ns1
            address: 192.168.10.1
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
from ..module_utils.api import NIOS_NSGROUP_FORWARDINGMEMBER
from ..module_utils.api import normalize_ib_spec


def main():
    '''entrypoint for module execution.'''

    argument_spec = dict(
        provider=dict(required=True),
        state=dict(default='present', choices=['present', 'absent']),
    )

    forward_to_spec = dict(
        name=dict(required=True),
        address=dict(required=True),
    )

    forwarding_servers_spec = dict(
        name=dict(required=True),
        forwarders_only=dict(type='bool', default=False),
        forward_to=dict(type='list', elements='dict', options=forward_to_spec, default=[], required=False),
        use_override_forwarders=dict(type='bool', default=False),
    )

    ib_spec = dict(
        name=dict(required=True, ib_req=True),
        forwarding_servers=dict(type='list', elements='dict', required=True, options=forwarding_servers_spec),
        extattrs=dict(type='dict'),
        comment=dict(),
    )

    argument_spec.update(normalize_ib_spec(ib_spec))
    argument_spec.update(WapiModule.provider_spec)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    wapi = WapiModule(module)
    result = wapi.run(NIOS_NSGROUP_FORWARDINGMEMBER, ib_spec)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
