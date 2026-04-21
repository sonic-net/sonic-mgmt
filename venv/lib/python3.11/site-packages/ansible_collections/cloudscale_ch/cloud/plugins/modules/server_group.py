#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2019, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: server_group
short_description: Manages server groups on the cloudscale.ch IaaS service
description:
  - Create, update and remove server groups.
author:
  - René Moser (@resmo)
  - Denis Krienbühl (@href)
version_added: "1.0.0"
options:
  name:
    description:
      - Name of the server group.
      - Either I(name) or I(uuid) is required. These options are mutually exclusive.
    type: str
  uuid:
    description:
      - UUID of the server group.
      - Either I(name) or I(uuid) is required. These options are mutually exclusive.
    type: str
  type:
    description:
      - Type of the server group.
    default: anti-affinity
    type: str
  zone:
    description:
      - Zone slug of the server group (e.g. C(lpg1) or C(rma1)).
    type: str
  state:
    description:
      - State of the server group.
    choices: [ present, absent ]
    default: present
    type: str
  tags:
    description:
      - Tags assosiated with the server groups. Set this to C({}) to clear any tags.
    type: dict
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = '''
---
- name: Ensure server group exists
  cloudscale_ch.cloud.server_group:
    name: my-name
    type: anti-affinity
    api_token: xxxxxx

- name: Ensure server group in a specific zone
  cloudscale_ch.cloud.server_group:
    name: my-rma-group
    type: anti-affinity
    zone: lpg1
    api_token: xxxxxx

- name: Ensure a server group is absent
  cloudscale_ch.cloud.server_group:
    name: my-name
    state: absent
    api_token: xxxxxx
'''

RETURN = '''
---
href:
  description: API URL to get details about this server group
  returned: if available
  type: str
  sample: https://api.cloudscale.ch/v1/server-group/cfde831a-4e87-4a75-960f-89b0148aa2cc
uuid:
  description: The unique identifier for this server
  returned: always
  type: str
  sample: cfde831a-4e87-4a75-960f-89b0148aa2cc
name:
  description: The display name of the server group
  returned: always
  type: str
  sample: load balancers
type:
  description: The type the server group
  returned: if available
  type: str
  sample: anti-affinity
zone:
  description: The zone of the server group
  returned: success
  type: dict
  sample: { 'slug': 'rma1' }
servers:
  description: A list of servers that are part of the server group.
  returned: if available
  type: list
  sample: []
state:
  description: State of the server group.
  returned: always
  type: str
  sample: present
tags:
  description: Tags assosiated with the server group.
  returned: success
  type: dict
  sample: { 'project': 'my project' }
'''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.api import (
    AnsibleCloudscaleBase,
    cloudscale_argument_spec,
)


def main():
    argument_spec = cloudscale_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str'),
        uuid=dict(type='str'),
        type=dict(type='str', default='anti-affinity'),
        zone=dict(type='str'),
        tags=dict(type='dict'),
        state=dict(default='present', choices=['absent', 'present']),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(('name', 'uuid'),),
        required_if=(('state', 'present', ('name',),),),
        supports_check_mode=True,
    )

    cloudscale_server_group = AnsibleCloudscaleBase(
        module,
        resource_name='server-groups',
        resource_create_param_keys=[
            'name',
            'type',
            'zone',
            'tags',
        ],
        resource_update_param_keys=[
            'name',
            'tags',
        ],
    )
    cloudscale_server_group.query_constraint_keys = [
        'zone',
    ]

    if module.params['state'] == 'absent':
        result = cloudscale_server_group.absent()
    else:
        result = cloudscale_server_group.present()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
