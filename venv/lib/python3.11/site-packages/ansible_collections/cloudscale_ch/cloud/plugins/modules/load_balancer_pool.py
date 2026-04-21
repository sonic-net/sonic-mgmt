#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, Gaudenz Steinlin <gaudenz.steinlin@cloudscale.ch>
# Copyright: (c) 2023, Kenneth Joss <kenneth.joss@cloudscale.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: load_balancer_pool
short_description: Manages load balancer pools on the cloudscale.ch IaaS service
description:
  - Get, create, update, delete pools on the cloudscale.ch IaaS service.
notes:
  - If I(uuid) option is provided, it takes precedence over I(name) for pool selection. This allows to update the load balancer pool's name.
  - If no I(uuid) option is provided, I(name) is used for pool selection. If more than one pool with this name exists, execution is aborted.
author:
  - Gaudenz Steinlin (@gaudenz)
  - Kenneth Joss (@k-304)
version_added: "2.3.0"
options:
  state:
    description:
      - State of the load balancer pool.
    choices: [ present, absent ]
    default: present
    type: str
  name:
    description:
      - Name of the load balancer pool.
    type: str
  uuid:
    description:
      - UUID of the load balancer pool.
      - Either I(name) or I(uuid) are required.
    type: str
  load_balancer:
    description:
      - UUID of the load balancer for this pool.
    type: str
  algorithm:
    description:
      - The algorithm according to which the incoming traffic is distributed between the pool members.
      - See the [API documentation](https://www.cloudscale.ch/en/api/v1#pool-algorithms) for supported distribution algorithms.
    type: str
  protocol:
    description:
      - The protocol used for traffic between the load balancer and the pool members.
      - See the [API documentation](https://www.cloudscale.ch/en/api/v1#pool-protocols) for supported protocols.
    type: str
  tags:
    description:
      - Tags assosiated with the load balancer. Set this to C({}) to clear any tags.
    type: dict
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = '''
# Create a pool for a load balancer using registered variables
- name: Create a running load balancer
  cloudscale_ch.cloud.load_balancer:
    name: 'lb1'
    flavor: 'lb-standard'
    zone: 'lpg1'
    tags:
      project: ansible-test
      stage: production
      sla: 24-7
    api_token: xxxxxx
  register: load_balancer

- name: Create a load balancer pool
  cloudscale_ch.cloud.load_balancer_pool:
    name: 'swimming-pool'
    load_balancer: '{{ load_balancer.uuid }}'
    algorithm: 'round_robin'
    protocol: 'tcp'
    tags:
      project: ansible-test
      stage: production
      sla: 24-7
    api_token: xxxxxx
  register: load_balancer_pool

# Create a load balancer pool with algorithm: round_robin and protocol: tcp
- name: Create a load balancer pool
  cloudscale_ch.cloud.load_balancer_pool:
    name: 'cloudscale-loadbalancer-pool1'
    load_balancer: '3766c579-3012-4a85-8192-2bbb4ef85b5f'
    algorithm: 'round_robin'
    protocol: 'tcp'
    tags:
      project: ansible-test
      stage: production
      sla: 24-7
    api_token: xxxxxx

# Get load balancer pool facts by name
- name: Get facts of a load balancer pool
  cloudscale_ch.cloud.load_balancer_pool:
    name: cloudscale-loadbalancer-pool1
    api_token: xxxxxx
'''

RETURN = '''
href:
  description: API URL to get details about this load balancer
  returned: success when not state == absent
  type: str
  sample: https://api.cloudscale.ch/v1/load-balancers/pools/
uuid:
  description: The unique identifier for this load balancer pool
  returned: success
  type: str
  sample: 3766c579-3012-4a85-8192-2bbb4ef85b5f
name:
  description: The display name of the load balancer pool
  returned: success
  type: str
  sample: web-lb-pool1
created_at:
  description: The creation date and time of the load balancer pool
  returned: success when not state == absent
  type: str
  sample: "2023-02-07T15:32:02.308041Z"
load_balancer:
  description: The load balancer this pool is connected to
  returned: success when not state == absent
  type: list
  sample: {
            "href": "https://api.cloudscale.ch/v1/load-balancers/15264769-ac69-4809-a8e4-4d73f8f92496",
            "uuid": "15264769-ac69-4809-a8e4-4d73f8f92496",
            "name": "web-lb"
          }
algorithm:
  description: The algorithm according to which the incoming traffic is distributed between the pool members
  returned: success
  type: str
  sample: round_robin
protocol:
  description: The protocol used for traffic between the load balancer and the pool members
  returned: success
  type: str
  sample: tcp
state:
  description: The current state of the load balancer pool
  returned: success
  type: str
  sample: present
tags:
  description: Tags assosiated with the load balancer
  returned: success
  type: dict
  sample: { 'project': 'my project' }
'''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.api import (
    AnsibleCloudscaleBase,
    cloudscale_argument_spec,
)

ALLOWED_STATES = ('present',
                  'absent',
                  )


def main():
    argument_spec = cloudscale_argument_spec()
    argument_spec.update(dict(
        name=dict(),
        uuid=dict(),
        load_balancer=dict(),
        algorithm=dict(type='str'),
        protocol=dict(type='str'),
        tags=dict(type='dict'),
        state=dict(default='present', choices=ALLOWED_STATES),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=(),
        required_one_of=(('name', 'uuid'),),
        required_if=(('state', 'present', ('name',),),),
        supports_check_mode=True,
    )

    cloudscale_load_balancer_pool = AnsibleCloudscaleBase(
        module,
        resource_name='load-balancers/pools',
        resource_create_param_keys=[
            'name',
            'load_balancer',
            'algorithm',
            'protocol',
            'tags',
        ],
        resource_update_param_keys=[
            'name',
            'tags',
        ],
    )
    cloudscale_load_balancer_pool.query_constraint_keys = []

    if module.params['state'] == "absent":
        result = cloudscale_load_balancer_pool.absent()
    else:
        result = cloudscale_load_balancer_pool.present()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
