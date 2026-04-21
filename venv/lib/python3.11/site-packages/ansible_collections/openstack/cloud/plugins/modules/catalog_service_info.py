#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 by Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = r'''
module: catalog_service_info
short_description: Retrieve information about services from OpenStack
author: OpenStack Ansible SIG
description:
    - Retrieve information about services from OpenStack.
options:
    name:
      description:
        - Name or ID of the service.
      type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Fetch all services
  openstack.cloud.catalog_service_info:
    cloud: devstack

- name: Fetch a single service
  openstack.cloud.catalog_service_info:
    cloud: devstack
    name: heat
'''

RETURN = r'''
services:
    description: List of dictionaries the services.
    returned: always
    type: list
    elements: dict
    contains:
        id:
            description: Service ID.
            type: str
            sample: "3292f020780b4d5baf27ff7e1d224c44"
        name:
            description: Service name.
            type: str
            sample: "glance"
        type:
            description: Service type.
            type: str
            sample: "image"
        description:
            description: Service description.
            type: str
            sample: "OpenStack Image Service"
        is_enabled:
            description: Service status.
            type: bool
            sample: True
        links:
            description: Link of the service
            type: str
            sample: http://10.0.0.1/identity/v3/services/0ae87
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule
)


class CatalogServiceInfoModule(OpenStackModule):
    argument_spec = dict(
        name=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True,
    )

    def run(self):
        name_or_id = self.params['name']

        if name_or_id:
            service = self.conn.identity.find_service(name_or_id)
            services = [service] if service else []
        else:
            services = self.conn.identity.services()

        self.exit_json(changed=False,
                       services=[s.to_dict(computed=False) for s in services])


def main():
    module = CatalogServiceInfoModule()
    module()


if __name__ == "__main__":
    main()
