#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2016 Sam Yaple
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: catalog_service
short_description: Manage OpenStack services
author: OpenStack Ansible SIG
description:
    - Create, update or delete a OpenStack service.
options:
   name:
     description:
        - Name of the service.
     required: true
     type: str
   description:
     description:
        - Description of the service.
     type: str
   is_enabled:
     description:
        - Whether this service is enabled or not.
     type: bool
     aliases: ['enabled']
   type:
     description:
        - The type of service.
     required: true
     type: str
     aliases: ['service_type']
   state:
     description:
      - Whether the service should be C(present) or C(absent).
     choices: ['present', 'absent']
     default: present
     type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Create a service for glance
  openstack.cloud.catalog_service:
     cloud: mycloud
     state: present
     name: glance
     type: image
     description: OpenStack Image Service

- name: Delete a service
  openstack.cloud.catalog_service:
     cloud: mycloud
     state: absent
     name: glance
     type: image
'''

RETURN = r'''
service:
    description: Dictionary describing the service.
    returned: On success when I(state) is 'present'
    type: dict
    contains:
        description:
            description: Service description.
            type: str
            sample: "OpenStack Image Service"
        id:
            description: Service ID.
            type: str
            sample: "3292f020780b4d5baf27ff7e1d224c44"
        is_enabled:
            description: Service status.
            type: bool
            sample: True
        links:
            description: Link of the service
            type: str
            sample: http://10.0.0.1/identity/v3/services/0ae87
        name:
            description: Service name.
            type: str
            sample: "glance"
        type:
            description: Service type.
            type: str
            sample: "image"
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class CatalogServiceModule(OpenStackModule):
    argument_spec = dict(
        description=dict(),
        is_enabled=dict(aliases=['enabled'], type='bool'),
        name=dict(required=True),
        type=dict(required=True, aliases=['service_type']),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        state = self.params['state']

        service = self._find()

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, service))

        if state == 'present' and not service:
            # Create service
            service = self._create()
            self.exit_json(changed=True,
                           service=service.to_dict(computed=False))

        elif state == 'present' and service:
            # Update service
            update = self._build_update(service)
            if update:
                service = self._update(service, update)

            self.exit_json(changed=bool(update),
                           service=service.to_dict(computed=False))

        elif state == 'absent' and service:
            # Delete service
            self._delete(service)
            self.exit_json(changed=True)

        elif state == 'absent' and not service:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, service):
        update = {}

        non_updateable_keys = [k for k in ['name']
                               if self.params[k] is not None
                               and self.params[k] != service[k]]

        if non_updateable_keys:
            self.fail_json(msg='Cannot update parameters {0}'
                               .format(non_updateable_keys))

        attributes = dict((k, self.params[k])
                          for k in ['description', 'is_enabled', 'type']
                          if self.params[k] is not None
                          and self.params[k] != service[k])

        if attributes:
            update['attributes'] = attributes

        return update

    def _create(self):
        kwargs = dict((k, self.params[k])
                      for k in ['description', 'is_enabled', 'name', 'type']
                      if self.params[k] is not None)

        return self.conn.identity.create_service(**kwargs)

    def _delete(self, service):
        self.conn.identity.delete_service(service.id)

    def _find(self):
        kwargs = dict((k, self.params[k]) for k in ['name', 'type'])
        matches = list(self.conn.identity.services(**kwargs))

        if len(matches) > 1:
            self.fail_json(msg='Found more a single service'
                               ' matching the given parameters.')
        elif len(matches) == 1:
            return matches[0]
        else:  # len(matches) == 0
            return None

    def _update(self, service, update):
        attributes = update.get('attributes')
        if attributes:
            service = self.conn.identity.update_service(service.id,
                                                        **attributes)

        return service

    def _will_change(self, state, service):
        if state == 'present' and not service:
            return True
        elif state == 'present' and service:
            return bool(self._build_update(service))
        elif state == 'absent' and service:
            return True
        else:
            # state == 'absent' and not service:
            return False


def main():
    module = CatalogServiceModule()
    module()


if __name__ == '__main__':
    main()
