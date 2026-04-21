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
module: load_balancer
short_description: Manages load balancers on the cloudscale.ch IaaS service
description:
  - Get, create, update, delete load balancers on the cloudscale.ch IaaS service.
notes:
  - If I(uuid) option is provided, it takes precedence over I(name) for load balancer selection. This allows to update the load balancers's name.
  - If no I(uuid) option is provided, I(name) is used for load balancer selection. If more than one load balancer with this name exists, execution is aborted.
author:
  - Gaudenz Steinlin (@gaudenz)
  - Kenneth Joss (@k-304)
version_added: "2.3.0"
options:
  state:
    description:
      - State of the load balancer.
    choices: [ present, absent ]
    default: present
    type: str
  name:
    description:
      - Name of the load balancer.
      - Either I(name) or I(uuid) are required.
    type: str
  uuid:
    description:
      - UUID of the load balancer.
      - Either I(name) or I(uuid) are required.
    type: str
  flavor:
    description:
      - Flavor of the load balancer.
    default: lb-standard
    type: str
  vip_addresses:
    description:
      - See the [API documentation](https://www.cloudscale.ch/en/api/v1#vip_addresses-attribute-specification) for details about this parameter.
    type: list
    elements: dict
    suboptions:
      subnet:
        description:
          - Create a VIP address on the subnet identified by this UUID.
        type: str
      address:
        description:
          - Use this address.
          - Must be in the same range as subnet.
          - If empty, a radom address will be used.
        type: str
  zone:
    description:
      - Zone in which the load balancer resides (e.g. C(lpg1) or C(rma1)).
    type: str
  tags:
    description:
      - Tags assosiated with the load balancer. Set this to C({}) to clear any tags.
    type: dict
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = '''
# Create and start a load balancer
- name: Start cloudscale.ch load balancer
  cloudscale_ch.cloud.load_balancer:
    name: my-shiny-cloudscale-load-balancer
    flavor: lb-standard
    zone: rma1
    tags:
      project: my project
    api_token: xxxxxx

# Create and start a load balancer with specific subnet
- name: Start cloudscale.ch load balancer
  cloudscale_ch.cloud.load_balancer:
    name: my-shiny-cloudscale-load-balancer
    flavor: lb-standard
    vip_addresses:
      - subnet: d7b82c9b-5900-436c-9296-e94dca01c7a0
        address: 172.25.12.1
    zone: lpg1
    tags:
      project: my project
    api_token: xxxxxx

# Get load balancer facts by name
- name: Get facts of a load balancer
  cloudscale_ch.cloud.load_balancer:
    name: my-shiny-cloudscale-load-balancer
    api_token: xxxxxx
'''

RETURN = '''
href:
  description: API URL to get details about this load balancer
  returned: success when not state == absent
  type: str
  sample: https://api.cloudscale.ch/v1/load-balancers/0f62e0a7-f459-4fc4-9c25-9e57b6cb4b2f
uuid:
  description: The unique identifier for this load balancer
  returned: success
  type: str
  sample: cfde831a-4e87-4a75-960f-89b0148aa2cc
name:
  description: The display name of the load balancer
  returned: success
  type: str
  sample: web-lb
created_at:
  description: The creation date and time of the load balancer
  returned: success when not state == absent
  type: str
  sample: "2023-02-07T15:32:02.308041Z"
status:
  description: The current operational status of the load balancer
  returned: success
  type: str
  sample: running
state:
  description: The current state of the load balancer
  returned: success
  type: str
  sample: present
zone:
  description: The zone used for this load balancer
  returned: success when not state == absent
  type: dict
  sample: { 'slug': 'lpg1' }
flavor:
  description: The flavor that has been used for this load balancer
  returned: success when not state == absent
  type: list
  sample: { "slug": "lb-standard", "name": "LB-Standard" }
vip_addresses:
  description: List of vip_addresses for this load balancer
  returned: success when not state == absent
  type: dict
  sample: [ {"version": "4", "address": "192.0.2.110",
            "subnet": [
                "href": "https://api.cloudscale.ch/v1/subnets/92c70b2f-99cb-4811-8823-3d46572006e4",
                "uuid": "92c70b2f-99cb-4811-8823-3d46572006e4",
                "cidr": "192.0.2.0/24"
            ]} ]
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


class AnsibleCloudscaleLoadBalancer(AnsibleCloudscaleBase):

    def __init__(self, module):
        super(AnsibleCloudscaleLoadBalancer, self).__init__(
            module,
            resource_name='load-balancers',
            resource_create_param_keys=[
                'name',
                'flavor',
                'zone',
                'vip_addresses',
                'tags',
            ],
            resource_update_param_keys=[
                'name',
                'tags',
            ],
        )

    def create(self, resource, data=None):
        super().create(resource)
        if not self._module.check_mode:
            resource = self.wait_for_state('status', ('running', ))
        return resource


def main():
    argument_spec = cloudscale_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str'),
        uuid=dict(type='str'),
        flavor=dict(type='str', default='lb-standard'),
        zone=dict(type='str'),
        vip_addresses=dict(
            type='list',
            elements='dict',
            options=dict(
                subnet=dict(type='str'),
                address=dict(type='str'),
            ),
        ),
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

    cloudscale_load_balancer = AnsibleCloudscaleLoadBalancer(module)
    cloudscale_load_balancer.query_constraint_keys = [
        'zone',
    ]

    if module.params['state'] == "absent":
        result = cloudscale_load_balancer.absent()
    else:
        result = cloudscale_load_balancer.present()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
