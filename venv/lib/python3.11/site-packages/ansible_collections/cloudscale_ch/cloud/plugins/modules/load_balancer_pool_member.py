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
module: load_balancer_pool_member
short_description: Manages load balancer pool members on the cloudscale.ch IaaS service
description:
  - Get, create, update, delete pool members on the cloudscale.ch IaaS service.
notes:
  - If I(uuid) option is provided, it takes precedence over I(name) for pool member selection. This allows to update the member's name.
  - If no I(uuid) option is provided, I(name) is used for pool member selection. If more than one load balancer with this name exists, execution is aborted.
author:
  - Gaudenz Steinlin (@gaudenz)
  - Kenneth Joss (@k-304)
version_added: "2.3.0"
options:
  state:
    description:
      - State of the load balancer pool member.
    choices: [ present, absent ]
    default: present
    type: str
  name:
    description:
      - Name of the load balancer pool member.
      - Either I(name) or I(uuid) are required.
    type: str
  uuid:
    description:
      - UUID of the load balancer.
      - Either I(name) or I(uuid) are required.
    type: str
  load_balancer_pool:
    description:
      - UUID of the load balancer pool.
    type: str
  enabled:
    description:
      - Pool member will not receive traffic if false. Default is true.
    default: true
    type: bool
  protocol_port:
    description:
      - The port to which actual traffic is sent.
    type: int
  monitor_port:
    description:
      - The port to which health monitor checks are sent.
      - If not specified, protocol_port will be used. Default is null.
    default: null
    type: int
  address:
    description:
      - The IP address to which traffic is sent.
    type: str
  subnet:
    description:
      - The subnet of the address must be specified here.
    type: str
  tags:
    description:
      - Tags assosiated with the load balancer. Set this to C({}) to clear any tags.
    type: dict
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = '''
# Create a pool member for a load balancer pool using registered variables
- name: Create a load balancer pool
  cloudscale_ch.cloud.load_balancer_pool:
    name: 'swimming-pool'
    load_balancer: '514064c2-cfd4-4b0c-8a4b-c68c552ff84f'
    algorithm: 'round_robin'
    protocol: 'tcp'
    tags:
      project: ansible-test
      stage: production
      sla: 24-7
    api_token: xxxxxx
  register: load_balancer_pool

- name: Create a load balancer pool member
  cloudscale_ch.cloud.load_balancer_pool_member:
    name: 'my-shiny-swimming-pool-member'
    load_balancer_pool: '{{ load_balancer_pool.uuid }}'
    enabled: true
    protocol_port: 8080
    monitor_port: 8081
    subnet: '70d282ab-2a01-4abb-ada5-34e56a5a7eee'
    address: '172.16.0.100'
    tags:
      project: ansible-test
      stage: production
      sla: 24-7
    api_token: xxxxxx

# Get load balancer pool member facts by name
- name: Get facts of a load balancer pool member by name
  cloudscale_ch.cloud.load_balancer_pool_member:
    name: 'my-shiny-swimming-pool-member'
    api_token: xxxxxx
'''

RETURN = '''
href:
  description: API URL to get details about this load balancer
  returned: success when not state == absent
  type: str
  sample: https://api.cloudscale.ch/v1/load-balancers/pools/20a7eb11-3e17-4177-b46d-36e13b101d1c/members/b9991773-857d-47f6-b20b-0a03709529a9
uuid:
  description: The unique identifier for this load balancer pool member
  returned: success
  type: str
  sample: cfde831a-4e87-4a75-960f-89b0148aa2cc
name:
  description: The display name of the load balancer pool member
  returned: success
  type: str
  sample: web-lb-pool
enabled:
  description: THe status of the load balancer pool member
  returned: success
  type: bool
  sample: true
created_at:
  description: The creation date and time of the load balancer pool member
  returned: success when not state == absent
  type: str
  sample: "2023-02-07T15:32:02.308041Z"
pool:
  description: The pool of the pool member
  returned: success
  type: dict
  sample: {
            "href": "https://api.cloudscale.ch/v1/load-balancers/pools/20a7eb11-3e17-4177-b46d-36e13b101d1c",
            "uuid": "20a7eb11-3e17-4177-b46d-36e13b101d1c",
            "name": "web-lb-pool"
            }
protocol_port:
  description: The port to which actual traffic is sent
  returned: success
  type: int
  sample: 8080
monitor_port:
  description: The port to which health monitor checks are sent
  returned: success
  type: int
  sample: 8081
address:
  description: The IP address to which traffic is sent
  returned: success
  type: str
  sample: 10.11.12.3
subnet:
  description: The subnet in a private network in which address is located
  returned: success
  type: dict
  sample: {
            "href": "https://api.cloudscale.ch/v1/subnets/70d282ab-2a01-4abb-ada5-34e56a5a7eee",
            "uuid": "70d282ab-2a01-4abb-ada5-34e56a5a7eee",
            "cidr": "10.11.12.0/24"
            }
monitor_status:
  description: The status of the pool's health monitor check for this member
  returned: success
  type: str
  sample: up
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


class AnsibleCloudscaleLoadBalancerPoolMember(AnsibleCloudscaleBase):

    def __init__(self, module):
        super(AnsibleCloudscaleLoadBalancerPoolMember, self).__init__(
            module,
            resource_name='load-balancers/pools/%s/members' % module.params['load_balancer_pool'],
            resource_create_param_keys=[
                'name',
                'enabled',
                'protocol_port',
                'monitor_port',
                'address',
                'subnet',
                'tags',
            ],
            resource_update_param_keys=[
                'name',
                'enabled',
                'tags',
            ],
        )

    def query(self):
        # Initialize
        self._resource_data = self.init_resource()

        # Query by UUID
        uuid = self._module.params[self.resource_key_uuid]
        if uuid is not None:

            # network id case
            if "/" in uuid:
                uuid = uuid.split("/")[0]

            resource = self._get('%s/%s' % (self.resource_name, uuid))
            if resource:
                self._resource_data = resource
                self._resource_data['state'] = "present"

        # Query by name
        else:
            name = self._module.params[self.resource_key_name]

            # Resource has no name field, we use a defined tag as name
            if self.use_tag_for_name:
                resources = self._get('%s?tag:%s=%s' % (self.resource_name, self.resource_name_tag, name))
            else:
                resources = self._get('%s' % self.resource_name)

            matching = []
            if resources is None:
                self._module.fail_json(
                    msg="The load balancer pool %s does not exist."
                        % (self.resource_name,)
                )
            for resource in resources:
                if self.use_tag_for_name:
                    resource[self.resource_key_name] = resource['tags'].get(self.resource_name_tag)

                # Skip resource if constraints is not given e.g. in case of floating_ip the ip_version differs
                for constraint_key in self.query_constraint_keys:
                    if self._module.params[constraint_key] is not None:
                        if constraint_key == 'zone':
                            resource_value = resource['zone']['slug']
                        else:
                            resource_value = resource[constraint_key]

                        if resource_value != self._module.params[constraint_key]:
                            break
                else:
                    if resource[self.resource_key_name] == name:
                        matching.append(resource)

            # Fail on more than one resource with identical name
            if len(matching) > 1:
                self._module.fail_json(
                    msg="More than one %s resource with '%s' exists: %s. "
                        "Use the '%s' parameter to identify the resource." % (
                            self.resource_name,
                            self.resource_key_name,
                            name,
                            self.resource_key_uuid
                        )
                )
            elif len(matching) == 1:
                self._resource_data = matching[0]
                self._resource_data['state'] = "present"

        return self.pre_transform(self._resource_data)


def main():
    argument_spec = cloudscale_argument_spec()
    argument_spec.update(dict(
        name=dict(),
        uuid=dict(),
        load_balancer_pool=dict(type='str'),
        enabled=dict(type='bool', default=True),
        protocol_port=dict(type='int'),
        monitor_port=dict(type='int'),
        subnet=dict(type='str'),
        address=dict(type='str'),
        tags=dict(type='dict'),
        state=dict(default='present', choices=ALLOWED_STATES),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=(),
        required_one_of=(('name', 'uuid'),),
        supports_check_mode=True,
    )

    cloudscale_load_balancer_pool_member = AnsibleCloudscaleLoadBalancerPoolMember(module)
    cloudscale_load_balancer_pool_member.query_constraint_keys = []

    if module.params['state'] == "absent":
        result = cloudscale_load_balancer_pool_member.absent()
    else:
        result = cloudscale_load_balancer_pool_member.present()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
