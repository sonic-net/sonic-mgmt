#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2020, René Moser <rene.moser@cloudscale.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: subnet
short_description: Manages subnets on the cloudscale.ch IaaS service
description:
  - Create, update and remove subnets.
author:
  - René Moser (@resmo)
version_added: "1.3.0"
options:
  uuid:
    description:
      - UUID of the subnet.
    type: str
  cidr:
    description:
      - The cidr of the subnet.
      - Required if I(state=present).
    type: str
  network:
    description:
      - The name of the network the subnet is related to.
      - Required if I(state=present).
    type: dict
    suboptions:
      uuid:
        description:
          - The uuid of the network.
        type: str
      name:
        description:
          - The uuid of the network.
        type: str
      zone:
        description:
          - The zone the network allocated in.
        type: str
  gateway_address:
    description:
      - The gateway address of the subnet. If not set, no gateway is used.
      - Cannot be within the DHCP range, which is the lowest .101-.254 in the subnet.
    type: str
  dns_servers:
    description:
      - A list of DNS resolver IP addresses, that act as DNS servers.
      - If not set, the cloudscale.ch default resolvers are used.
    type: list
    elements: str
  reset:
    description:
      - Resets I(gateway_address) and I(dns_servers) to default values by the API.
      - "Note: Idempotency is not given."
    type: bool
    default: false
  state:
    description:
      - State of the subnet.
    choices: [ present, absent ]
    default: present
    type: str
  tags:
    description:
      - Tags associated with the subnet. Set this to C({}) to clear any tags.
    type: dict
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = '''
---
- name: Ensure subnet exists
  cloudscale_ch.cloud.subnet:
    cidr: 172.16.0.0/24
    network:
      uuid: 2db69ba3-1864-4608-853a-0771b6885a3a
    api_token: xxxxxx

- name: Ensure subnet exists
  cloudscale_ch.cloud.subnet:
    cidr: 192.168.1.0/24
    gateway_address: 192.168.1.1
    dns_servers:
      - 192.168.1.10
      - 192.168.1.11
    network:
      name: private
      zone: lpg1
    api_token: xxxxxx

- name: Ensure a subnet is absent
  cloudscale_ch.cloud.subnet:
    cidr: 172.16.0.0/24
    network:
      name: private
      zone: lpg1
    state: absent
    api_token: xxxxxx
'''

RETURN = '''
---
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
network:
  description: The network object of the subnet.
  returned: success
  type: complex
  contains:
    href:
      description: API URL to get details about the network.
      returned: success
      type: str
      sample: https://api.cloudscale.ch/v1/networks/33333333-1864-4608-853a-0771b6885a3
    uuid:
      description: The unique identifier for the network.
      returned: success
      type: str
      sample: 33333333-1864-4608-853a-0771b6885a3
    name:
      description: The name of the network.
      returned: success
      type: str
      sample: my network
    zone:
        description: The zone the network is allocated in.
        returned: success
        type: dict
        sample: { 'slug': 'rma1' }
        version_added: 1.4.0
gateway_address:
  description: The gateway address of the subnet.
  returned: success
  type: str
  sample: "192.168.42.1"
dns_servers:
  description: List of DNS resolver IP addresses.
  returned: success
  type: list
  sample: ["9.9.9.9", "149.112.112.112"]
state:
  description: State of the subnet.
  returned: success
  type: str
  sample: present
tags:
  description: Tags associated with the subnet.
  returned: success
  type: dict
  sample: { 'project': 'my project' }
'''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.api import (
    AnsibleCloudscaleBase,
    cloudscale_argument_spec,
)


class AnsibleCloudscaleSubnet(AnsibleCloudscaleBase):

    def __init__(self, module):
        super(AnsibleCloudscaleSubnet, self).__init__(
            module=module,
            resource_name='subnets',
            resource_key_name='cidr',
            resource_create_param_keys=[
                'cidr',
                'gateway_address',
                'dns_servers',
                'tags',
            ],
            resource_update_param_keys=[
                'gateway_address',
                'dns_servers',
                'tags',
            ],
        )
        self._network = None

    def query_network(self, uuid=None):
        if self._network is not None:
            return self._network

        net_param = self._module.params['network']
        net_uuid = uuid or net_param['uuid']

        if net_uuid is not None:
            network = self._get('networks/%s' % net_uuid)
            if not network:
                self._module.fail_json(msg="Network with 'uuid' not found: %s" % net_uuid)

        elif net_param['name'] is not None:
            networks_found = []
            networks = self._get('networks')
            for network in networks or []:
                # Skip networks in other zones
                if net_param['zone'] is not None and network['zone']['slug'] != net_param['zone']:
                    continue

                if network.get('name') == net_param['name']:
                    networks_found.append(network)

            if not networks_found:
                msg = "Network with 'name' not found: %s" % net_param['name']
                self._module.fail_json(msg=msg)

            elif len(networks_found) == 1:
                network = networks_found[0]

            # We might have found more than one network with identical name
            else:
                msg = ("Multiple networks with 'name' not found: %s."
                       "Add the 'zone' to distinguish or use 'uuid' argument to specify the network." % net_param['name'])
                self._module.fail_json(msg=msg)

        else:
            self._module.fail_json(msg="Either Network UUID or name is required.")

        # For consistency, take a minimal network stub, but also include zone
        self._network = dict()
        for k, v in network.items():
            if k in ['name', 'uuid', 'href', 'zone']:
                self._network[k] = v

        return self._network

    def create(self, resource):
        resource['network'] = self.query_network()

        data = {
            'network': resource['network']['uuid'],
        }
        return super(AnsibleCloudscaleSubnet, self).create(resource, data)

    def update(self, resource):
        # Resets to default values by the API
        if self._module.params.get('reset'):
            for key in ('dns_servers', 'gateway_address',):
                # No need to reset if user set the param anyway.
                if self._module.params.get(key) is None:
                    self._result['changed'] = True
                    patch_data = {
                        key: None
                    }
                if not self._module.check_mode:
                    href = resource.get('href')
                    if not href:
                        self._module.fail_json(msg='Unable to update %s, no href found.' % key)
                    self._patch(href, patch_data, filter_none=False)

            if not self._module.check_mode:
                resource = self.query()

        return super(AnsibleCloudscaleSubnet, self).update(resource)

    def get_result(self, resource):
        if resource and 'network' in resource:
            resource['network'] = self.query_network(uuid=resource['network']['uuid'])
        return super(AnsibleCloudscaleSubnet, self).get_result(resource)


def main():
    argument_spec = cloudscale_argument_spec()
    argument_spec.update(dict(
        uuid=dict(type='str'),
        cidr=dict(type='str'),
        network=dict(
            type='dict',
            options=dict(
                uuid=dict(type='str'),
                name=dict(type='str'),
                zone=dict(type='str'),
            ),
        ),
        gateway_address=dict(type='str'),
        dns_servers=dict(type='list', elements='str', default=None),
        tags=dict(type='dict'),
        reset=dict(type='bool', default=False),
        state=dict(default='present', choices=['absent', 'present']),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(('cidr', 'uuid',),),
        required_together=(('cidr', 'network',),),
        required_if=(('state', 'present', ('cidr', 'network',),),),
        supports_check_mode=True,
    )

    cloudscale_subnet = AnsibleCloudscaleSubnet(module)

    if module.params['state'] == 'absent':
        result = cloudscale_subnet.absent()
    else:
        result = cloudscale_subnet.present()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
