#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2020, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: network
short_description: Manages networks on the cloudscale.ch IaaS service
description:
  - Create, update and remove networks.
author:
  - René Moser (@resmo)
version_added: "1.2.0"
options:
  name:
    description:
      - Name of the network.
      - Either I(name) or I(uuid) is required.
    type: str
  uuid:
    description:
      - UUID of the network.
      - Either I(name) or I(uuid) is required.
    type: str
  mtu:
    description:
      - The MTU of the network.
    default: 9000
    type: int
  auto_create_ipv4_subnet:
    description:
      - Whether to automatically create an IPv4 subnet in the network or not.
    default: true
    type: bool
  zone:
    description:
      - Zone slug of the network (e.g. C(lpg1) or C(rma1)).
    type: str
  state:
    description:
      - State of the network.
    choices: [ present, absent ]
    default: present
    type: str
  tags:
    description:
      - Tags assosiated with the networks. Set this to C({}) to clear any tags.
    type: dict
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = '''
---
- name: Ensure network exists
  cloudscale_ch.cloud.network:
    name: my network
    api_token: xxxxxx

- name: Ensure network in a specific zone
  cloudscale_ch.cloud.network:
    name: my network
    zone: lpg1
    api_token: xxxxxx

- name: Ensure a network is absent
  cloudscale_ch.cloud.network:
    name: my network
    state: absent
    api_token: xxxxxx
'''

RETURN = '''
---
href:
  description: API URL to get details about this network.
  returned: success
  type: str
  sample: https://api.cloudscale.ch/v1/networks/cfde831a-4e87-4a75-960f-89b0148aa2cc
uuid:
  description: The unique identifier for the network.
  returned: success
  type: str
  sample: cfde831a-4e87-4a75-960f-89b0148aa2cc
name:
  description: The name of the network.
  returned: success
  type: str
  sample: my network
created_at:
  description: The creation date and time of the network.
  returned: success
  type: str
  sample: "2019-05-29T13:18:42.511407Z"
subnets:
  description: A list of subnets objects of the network.
  returned: success
  type: complex
  contains:
    href:
      description: API URL to get details about the subnet.
      returned: success
      type: str
      sample: https://api.cloudscale.ch/v1/subnets/33333333-1864-4608-853a-0771b6885a3
    uuid:
      description: The unique identifier for the subnet.
      returned: success
      type: str
      sample: 33333333-1864-4608-853a-0771b6885a3
    cidr:
      description: The CIDR of the subnet.
      returned: success
      type: str
      sample: 172.16.0.0/24
mtu:
  description: The MTU of the network.
  returned: success
  type: int
  sample: 9000
zone:
  description: The zone of the network.
  returned: success
  type: dict
  sample: { 'slug': 'rma1' }
state:
  description: State of the network.
  returned: success
  type: str
  sample: present
tags:
  description: Tags assosiated with the network.
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
        mtu=dict(type='int', default=9000),
        auto_create_ipv4_subnet=dict(type='bool', default=True),
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

    cloudscale_network = AnsibleCloudscaleBase(
        module,
        resource_name='networks',
        resource_create_param_keys=[
            'name',
            'mtu',
            'auto_create_ipv4_subnet',
            'zone',
            'tags',
        ],
        resource_update_param_keys=[
            'name',
            'mtu',
            'tags',
        ],
    )

    cloudscale_network.query_constraint_keys = [
        'zone',
    ]

    if module.params['state'] == 'absent':
        result = cloudscale_network.absent()
    else:
        result = cloudscale_network.present()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
