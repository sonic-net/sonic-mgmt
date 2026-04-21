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
module: load_balancer_listener
short_description: Manages load balancer listeners on the cloudscale.ch IaaS service
description:
  - Get, create, update, delete listeners on the cloudscale.ch IaaS service.
notes:
  - If I(uuid) option is provided, it takes precedence over I(name) for load balancer listener selection. This allows to update the listener's name.
  - If no I(uuid) option is provided, I(name) is used for load balancer listener selection.
  - If more than one load balancer with this name exists, execution is aborted.
author:
  - Gaudenz Steinlin (@gaudenz)
  - Kenneth Joss (@k-304)
version_added: "2.3.0"
options:
  state:
    description:
      - State of the load balancer listener.
    choices: [ present, absent ]
    default: present
    type: str
  name:
    description:
      - Name of the load balancer listener.
      - Either I(name) or I(uuid) are required.
    type: str
  uuid:
    description:
      - UUID of the load balancer listener.
      - Either I(name) or I(uuid) are required.
    type: str
  pool:
    description:
      - The pool of the listener.
    type: str
  protocol:
    description:
      - The protocol used for receiving traffic.
    type: str
  protocol_port:
    description:
      - The port on which traffic is received.
    type: int
  allowed_cidrs:
    description:
      - Restrict the allowed source IPs for this listener.
      - Empty means that any source IP is allowed. If the list is non-empty, traffic from source IPs not included is denied.
    type: list
    elements: str
  timeout_client_data_ms:
    description:
      - Client inactivity timeout in milliseconds.
    type: int
  timeout_member_connect_ms:
    description:
      - Pool member connection timeout in milliseconds.
    type: int
  timeout_member_data_ms:
    description:
      - Pool member inactivity timeout in milliseconds.
    type: int
  tags:
    description:
      - Tags assosiated with the load balancer. Set this to C({}) to clear any tags.
    type: dict
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = '''
# Create a load balancer listener for a pool using registered variables
- name: Create a load balancer pool
  cloudscale_ch.cloud.load_balancer_pool:
    name: 'swimming-pool'
    load_balancer: '3d41b118-f95c-4897-ad74-2260fea783fc'
    algorithm: 'round_robin'
    protocol: 'tcp'
    api_token: xxxxxx
  register: load_balancer_pool

- name: Create a load balancer listener
  cloudscale_ch.cloud.load_balancer_listener:
    name: 'swimming-pool-listener'
    pool: '{{ load_balancer_pool.uuid }}'
    protocol: 'tcp'
    protocol_port: 8080
    tags:
      project: ansible-test
      stage: production
      sla: 24-7
    api_token: xxxxxx

# Create a load balancer listener for a pool with restriction
- name: Create a load balancer listener with ip restriction
  cloudscale_ch.cloud.load_balancer_listener:
    name: 'new-listener2'
    pool: '618a6cc8-d757-4fab-aa10-d49dc47e667b'
    protocol: 'tcp'
    protocol_port: 8080
    allowed_cidrs:
      - '192.168.3.0/24'
      - '2001:db8:85a3:8d3::/64'
    tags:
      project: ansible-test
      stage: production
      sla: 24-7
    api_token: xxxxxx

# Get load balancer listener facts by name
- name: Get facts of a load balancer listener by name
  cloudscale_ch.cloud.load_balancer_listener:
    name: '{{ cloudscale_resource_prefix }}-test'
    api_token: xxxxxx
'''

RETURN = '''
href:
  description: API URL to get details about this load balancer lintener
  returned: success when not state == absent
  type: str
  sample: https://api.cloudscale.ch/v1/load-balancers/listeners/9fa91f17-fdb4-431f-8a59-78473f64e661
uuid:
  description: The unique identifier for this load balancer listener
  returned: success
  type: str
  sample: 9fa91f17-fdb4-431f-8a59-78473f64e661
name:
  description: The display name of the load balancer listener
  returned: success
  type: str
  sample: new-listener
created_at:
  description: The creation date and time of the load balancer listener
  returned: success when not state == absent
  type: str
  sample: "2023-02-07T15:32:02.308041Z"
pool:
  description: The pool of the load balancer listener
  returned: success when not state == absent
  type: complex
  contains:
    href:
      description: API URL to get details about the pool.
      returned: success
      type: str
      sample: https://api.cloudscale.ch/v1/load-balancers/pools/618a6cc8-d757-4fab-aa10-d49dc47e667b
    uuid:
      description: The unique identifier for the pool.
      returned: success
      type: str
      sample: 618a6cc8-d757-4fab-aa10-d49dc47e667b
    name:
      description: The name of the pool.
      returned: success
      type: str
      sample: new-listener
protocol:
  description: The protocol used for receiving traffic
  returned: success when not state == absent
  type: str
  sample: tcp
protocol_port:
  description: The port on which traffic is received
  returned: success when not state == absent
  type: int
  sample: 8080
allowed_cidrs:
  description: Restrict the allowed source IPs for this listener
  returned: success when not state == absent
  type: list
  sample: ["192.168.3.0/24", "2001:db8:85a3:8d3::/64"]
timeout_client_data_ms:
  description: Client inactivity timeout in milliseconds
  returned: success when not state == absent
  type: int
  sample: 50000
timeout_member_connect_ms:
  description: Pool member connection timeout in milliseconds
  returned: success when not state == absent
  type: int
  sample: 50000
timeout_member_data_ms:
  description: Pool member inactivity timeout in milliseconds
  returned: success when not state == absent
  type: int
  sample: 50000
tags:
  description: Tags assosiated with the load balancer listener
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
        name=dict(type='str'),
        uuid=dict(type='str'),
        pool=dict(type='str'),
        protocol=dict(type='str'),
        protocol_port=dict(type='int'),
        allowed_cidrs=dict(type='list', elements='str'),
        timeout_client_data_ms=dict(type='int'),
        timeout_member_connect_ms=dict(type='int'),
        timeout_member_data_ms=dict(type='int'),
        tags=dict(type='dict'),
        state=dict(type='str', default='present', choices=ALLOWED_STATES),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=(),
        required_one_of=(('name', 'uuid'),),
        required_if=(('state', 'present', ('name',),),),
        supports_check_mode=True,
    )

    cloudscale_load_balancer_listener = AnsibleCloudscaleBase(
        module,
        resource_name='load-balancers/listeners',
        resource_create_param_keys=[
            'name',
            'pool',
            'protocol',
            'protocol_port',
            'allowed_cidrs',
            'timeout_client_data_ms',
            'timeout_member_connect_ms',
            'timeout_member_data_ms',
            'tags',
        ],
        resource_update_param_keys=[
            'name',
            'allowed_cidrs',
            'timeout_client_data_ms',
            'timeout_member_connect_ms',
            'timeout_member_data_ms',
            'tags',
        ],
    )

    if module.params['state'] == "absent":
        result = cloudscale_load_balancer_listener.absent()
    else:
        result = cloudscale_load_balancer_listener.present()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
