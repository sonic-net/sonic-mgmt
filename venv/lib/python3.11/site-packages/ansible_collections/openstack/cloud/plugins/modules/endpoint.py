#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, VEXXHOST, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: endpoint
short_description: Manage OpenStack Identity service endpoints
author: OpenStack Ansible SIG
description:
    - Create, update, or delete OpenStack Identity service endpoints. If a
      service with the same combination of I(service), I(interface) and
      I(region) exist, the I(url), I(enabled) and I(state) (C(present) or
      C(absent)) will be updated.
options:
   service:
     description:
        - Name or id of the service.
     required: true
     type: str
   endpoint_interface:
     description:
        - Interface of the service.
     choices: [admin, public, internal]
     required: true
     type: str
   url:
     description:
        - URL of the service.
     required: true
     type: str
   region:
     description:
        - ID of the region that the service belongs to.
          Note that I(region) is used for authentication.
     type: str
   enabled:
     description:
        - Is the service enabled.
     default: True
     type: bool
   state:
     description:
       - Should the resource be C(present) or C(absent).
     choices: [present, absent]
     default: present
     type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
- name: Create a service for glance
  openstack.cloud.endpoint:
     cloud: mycloud
     service: glance
     endpoint_interface: public
     url: http://controller:9292
     region: RegionOne
     state: present

- name: Delete a service for nova
  openstack.cloud.endpoint:
     cloud: mycloud
     service: nova
     endpoint_interface: public
     region: RegionOne
     state: absent
'''

RETURN = '''
endpoint:
    description: Dictionary describing the endpoint.
    returned: On success when I(state) is C(present)
    type: dict
    contains:
        id:
            description: Endpoint ID.
            type: str
            sample: 3292f020780b4d5baf27ff7e1d224c44
        interface:
            description: Endpoint Interface.
            type: str
            sample: public
        is_enabled:
            description: Service status.
            type: bool
            sample: True
        links:
            description: Links for the endpoint
            type: str
            sample: http://controller/identity/v3/endpoints/123
        name:
            description: Name of the endpoint
            type: str
            sample: cinder
        region_id:
            description: Region ID.
            type: str
            sample: RegionOne
        service_id:
            description: Service ID.
            type: str
            sample: b91f1318f735494a825a55388ee118f3
        url:
            description: Service URL.
            type: str
            sample: http://controller:9292
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class IdentityEndpointModule(OpenStackModule):
    argument_spec = dict(
        service=dict(required=True),
        endpoint_interface=dict(required=True, choices=['admin', 'public', 'internal']),
        url=dict(required=True),
        region=dict(),
        enabled=dict(type='bool', default=True),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def _needs_update(self, endpoint):
        if endpoint.is_enabled != self.params['enabled']:
            return True
        if endpoint.url != self.params['url']:
            return True
        return False

    def _system_state_change(self, endpoint):
        state = self.params['state']
        if state == 'absent' and endpoint:
            return True

        if state == 'present':
            if endpoint is None:
                return True
            return self._needs_update(endpoint)

        return False

    def run(self):
        service_name_or_id = self.params['service']
        interface = self.params['endpoint_interface']
        url = self.params['url']
        # Regions have IDs but do not have names
        # Ref.: https://docs.openstack.org/api-ref/identity/v3/#regions
        region_id = self.params['region']
        enabled = self.params['enabled']
        state = self.params['state']

        service = self.conn.identity.find_service(service_name_or_id)

        if service is None and state == 'absent':
            self.exit_json(changed=False)

        if service is None and state == 'present':
            self.fail_json(msg='Service %s does not exist' % service_name_or_id)

        filters = dict(service_id=service.id, interface=interface)
        if region_id:
            filters['region_id'] = region_id
        endpoints = list(self.conn.identity.endpoints(**filters))

        endpoint = None
        if len(endpoints) > 1:
            self.fail_json(msg='Service %s, interface %s and region %s are '
                           'not unique' %
                           (service_name_or_id, interface, region_id))
        elif len(endpoints) == 1:
            endpoint = endpoints[0]

        if self.ansible.check_mode:
            self.exit_json(changed=self._system_state_change(endpoint))

        changed = False
        if state == 'present':
            if not endpoint:
                args = {
                    'url': url,
                    'interface': interface,
                    'service_id': service.id,
                    'enabled': enabled,
                    'region_id': region_id
                }

                endpoint = self.conn.identity.create_endpoint(**args)
                changed = True
            elif self._needs_update(endpoint):
                endpoint = self.conn.identity.update_endpoint(
                    endpoint.id, url=url, enabled=enabled)
                changed = True

            self.exit_json(changed=changed,
                           endpoint=endpoint.to_dict(computed=False))

        elif state == 'absent' and endpoint:
            self.conn.identity.delete_endpoint(endpoint.id)
            changed = True

        self.exit_json(changed=changed)


def main():
    module = IdentityEndpointModule()
    module()


if __name__ == '__main__':
    main()
