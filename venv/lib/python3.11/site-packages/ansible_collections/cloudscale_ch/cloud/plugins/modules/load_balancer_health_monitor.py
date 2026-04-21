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
module: load_balancer_health_monitor
short_description: Manages load balancers on the cloudscale.ch IaaS service
description:
  - Get, create, update, delete health monitors on the cloudscale.ch IaaS service.
notes:
  - Health monitors do not have names. I(uuid)'s are used to reference a health monitors.
author:
  - Gaudenz Steinlin (@gaudenz)
  - Kenneth Joss (@k-304)
version_added: "2.3.0"
options:
  state:
    description:
      - State of the load balancer health monitor.
    choices: [ present, absent ]
    default: present
    type: str
  uuid:
    description:
      - UUID of the load balancer health monitor.
    type: str
  pool:
    description:
      - The pool of the health monitor.
    type: str
  delay_s:
    description:
      - The delay between two successive checks in seconds.
    type: int
  timeout_s:
    description:
      - The maximum time allowed for an individual check in seconds.
    type: int
  up_threshold:
    description:
      - The number of checks that need to be successful before the monitor_status of a pool member changes to "up".
    type: int
  down_threshold:
    description:
      - The number of checks that need to fail before the monitor_status of a pool member changes to "down".
    type: int
  type:
    description:
      - The type of the health monitor.
      - See the [API documentation](https://www.cloudscale.ch/en/api/v1#create-a-health-monitor) for allowed options.
    type: str
  http:
    description:
      - Advanced options for health monitors with type "http" or "https".
    type: dict
    suboptions:
      expected_codes:
        description:
          - The HTTP status codes allowed for a check to be considered successful.
          - See the [API documentation](https://www.cloudscale.ch/en/api/v1#http-attribute-specification) for details.
        type: list
        elements: str
      method:
        description:
          - The HTTP method used for the check.
        type: str
      url_path:
        description:
          - The URL used for the check.
        type: str
      version:
        description:
          - The HTTP version used for the check.
        type: str
      host:
        description:
          - The server name in the HTTP Host header used for the check.
          - Requires version to be set to "1.1".
        type: str
  tags:
    description:
      - Tags assosiated with the load balancer. Set this to C({}) to clear any tags.
    type: dict
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = '''
# Create a simple health monitor for a pool
- name: Create a load balancer pool
  cloudscale_ch.cloud.load_balancer_pool:
    name: 'swimming-pool'
    load_balancer: '3d41b118-f95c-4897-ad74-2260fea783fc'
    algorithm: 'round_robin'
    protocol: 'tcp'
    api_token: xxxxxx
  register: load_balancer_pool

- name: Create a load balancer health monitor (ping)
  cloudscale_ch.cloud.load_balancer_health_monitor:
    pool: '{{ load_balancer_pool.uuid }}'
    type: 'ping'
    api_token: xxxxxx
  register: load_balancer_health_monitor

# Get load balancer health monitor facts by UUID
- name: Get facts of a load balancer health monitor by UUID
  cloudscale_ch.cloud.load_balancer_health_monitor:
    uuid: '{{ load_balancer_health_monitor.uuid }}'
    api_token: xxxxxx

# Update a health monitor
- name: Update HTTP method of a load balancer health monitor from GET to CONNECT
  cloudscale_ch.cloud.load_balancer_health_monitor:
    uuid: '{{ load_balancer_health_monitor_http.uuid }}'
    delay_s: 2
    timeout_s: 1
    up_threshold: 2
    down_threshold: 3
    type: 'http'
    http:
      expected_codes:
        - 200
        - 202
      method: 'CONNECT'
      url_path: '/'
      version: '1.1'
      host: 'host1'
    tags:
      project: ansible-test
      stage: production
      sla: 24-7
    api_token: xxxxxx
  register: load_balancer_health_monitor
'''

RETURN = '''
href:
  description: API URL to get details about this load balancer health monitor
  returned: success when not state == absent
  type: str
  sample: https://api.cloudscale.ch/v1/load-balancers/health-monitors/ee4952d4-2eba-4dec-8957-7911b3ce245b
uuid:
  description: The unique identifier for this load balancer health monitor
  returned: success
  type: str
  sample: ee4952d4-2eba-4dec-8957-7911b3ce245b
created_at:
  description: The creation date and time of the load balancer health monitor
  returned: success when not state == absent
  type: str
  sample: "2023-02-22T09:55:38.285018Z"
pool:
  description: The pool of the health monitor
  returned: success when not state == absent
  type: dict
  sample: [
            "href": "https://api.cloudscale.ch/v1/load-balancers/pools/618a6cc8-d757-4fab-aa10-d49dc47e667b",
            "uuid": "618a6cc8-d757-4fab-aa10-d49dc47e667b",
            "name": "swimming pool"
          ]
delay_s:
  description: The delay between two successive checks in seconds
  returned: success when not state == absent
  type: int
  sample: 2
timeout_s:
  description: The maximum time allowed for an individual check in seconds
  returned: success when not state == absent
  type: int
  sample: 1
up_threshold:
  description: The number of checks that need to be successful before the monitor_status of a pool member changes to "up"
  returned: success when not state == absent
  type: int
  sample: 2
down_threshold:
  description: The number of checks that need to fail before the monitor_status of a pool member changes to "down"
  returned: success when not state == absent
  type: int
  sample: 3
type:
  description: The type of the health monitor
  returned: success when not state == absent
  type: str
http:
  description: Advanced options for health monitors with type "http" or "https"
  returned: success when not state == absent
  type: dict
  sample: [ {
                "expected_codes": [
                    "200"
                ],
                "method": "GET",
                "url_path": "/",
                "version": "1.0",
                "host": null
            } ]
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
ALLOWED_HTTP_POST_PARAMS = ('expected_codes',
                            'host',
                            'method',
                            'url_path')


class AnsibleCloudscaleLoadBalancerHealthMonitor(AnsibleCloudscaleBase):

    def __init__(self, module):
        super(AnsibleCloudscaleLoadBalancerHealthMonitor, self).__init__(
            module,
            resource_name='load-balancers/health-monitors',
            resource_key_name='pool',
            resource_create_param_keys=[
                'pool',
                'timeout_s',
                'up_threshold',
                'down_threshold',
                'type',
                'http',
                'tags',
            ],
            resource_update_param_keys=[
                'delay_s',
                'timeout_s',
                'up_threshold',
                'down_threshold',
                'expected_codes',
                'http',
                'tags',
            ],
        )

    def query(self):
        # Initialize
        self._resource_data = self.init_resource()

        resource_key_pool = 'pool'
        uuid = self._module.params[self.resource_key_uuid]
        pool = self._module.params[resource_key_pool]
        matching = []

        # Either search by given health monitor's UUID or
        # search the health monitor by its acossiated pool UUID (1:1)
        if uuid is not None:
            super().query()
        else:
            pool = self._module.params[resource_key_pool]
            if pool is not None:

                resources = self._get('%s' % (self.resource_name))

                if resources:
                    for health_monitor in resources:
                        if health_monitor[resource_key_pool]['uuid'] == pool:
                            matching.append(health_monitor)

            # Fail on more than one resource with identical name
            if len(matching) > 1:
                self._module.fail_json(
                    msg="More than one %s resource for pool '%s' exists." % (
                        self.resource_name,
                        resource_key_pool
                    )
                )
            elif len(matching) == 1:
                self._resource_data = matching[0]
                self._resource_data['state'] = "present"

        return self.pre_transform(self._resource_data)

    def update(self, resource):
        updated = False
        for param in self.resource_update_param_keys:
            if param == 'http' and self._module.params.get('http') is not None:
                for subparam in ALLOWED_HTTP_POST_PARAMS:
                    updated = self._http_param_updated(subparam, resource) or updated
            else:
                updated = self._param_updated(param, resource) or updated

        # Refresh if resource was updated in live mode
        if updated and not self._module.check_mode:
            resource = self.query()
        return resource

    def _http_param_updated(self, key, resource):
        param_http = self._module.params.get('http')
        param = param_http[key]

        if param is None:
            return False

        if not resource or key not in resource['http']:
            return False

        is_different = self.find_http_difference(key, resource, param)

        if is_different:
            self._result['changed'] = True

            patch_data = {
                'http': {
                    key: param
                }
            }

            before_data = {
                'http': {
                    key: resource['http'][key]
                }
            }

            self._result['diff']['before'].update(before_data)
            self._result['diff']['after'].update(patch_data)

            if not self._module.check_mode:
                href = resource.get('href')
                if not href:
                    self._module.fail_json(msg='Unable to update %s, no href found.' % key)

                self._patch(href, patch_data)
                return True
        return False

    def find_http_difference(self, key, resource, param):
        is_different = False

        if param != resource['http'][key]:
            is_different = True

        return is_different


def main():
    argument_spec = cloudscale_argument_spec()
    argument_spec.update(dict(
        uuid=dict(type='str'),
        pool=dict(type='str'),
        delay_s=dict(type='int'),
        timeout_s=dict(type='int'),
        up_threshold=dict(type='int'),
        down_threshold=dict(type='int'),
        type=dict(type='str'),
        http=dict(
            type='dict',
            options=dict(
                expected_codes=dict(type='list', elements='str'),
                method=dict(type='str'),
                url_path=dict(type='str'),
                version=dict(type='str'),
                host=dict(type='str'),
            )
        ),
        tags=dict(type='dict'),
        state=dict(default='present', choices=ALLOWED_STATES),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=(),
        required_one_of=(),
        required_if=(),
        supports_check_mode=True,
    )

    cloudscale_load_balancer_health_monitor = AnsibleCloudscaleLoadBalancerHealthMonitor(module)
    cloudscale_load_balancer_health_monitor.query_constraint_keys = []

    if module.params['state'] == "absent":
        result = cloudscale_load_balancer_health_monitor.absent()
    else:
        result = cloudscale_load_balancer_health_monitor.present()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
