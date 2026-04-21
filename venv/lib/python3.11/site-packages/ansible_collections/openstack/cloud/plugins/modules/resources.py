#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Jakob Meng, <jakobmeng@web.de>
# Copyright (c) 2023 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: resources
short_description: List OpenStack cloud resources
author: OpenStack Ansible SIG
description:
  - List OpenStack cloud resources.
options:
  service:
    description:
      - OpenStack service which this resource is part of.
      - Examples are C(block_storage), C(compute) or C(network).
      - "I(service) must be a C(lowercase) name of a OpenStack service as
         used in openstacksdk. For a list of available services visit
         U(https://opendev.org/openstack/openstacksdk): Most subdirectories
         in the C(openstack) directory correspond to a OpenStack service,
         except C(cloud), C(common) and other auxiliary directories."
    required: true
    type: str
  parameters:
    description:
      - Query parameters passed to OpenStack API for results filtering.
      - I(attributes) is a set of key-value pairs where each key is a attribute
        name such as C(id) and value holds its corresponding attribute value
        such C(ddad2d86-02a6-444d-80ae-1cc2fb023784).
      - For a complete list of valid query parameters open any resource class
        inside openstacksdk such as file C(openstack/compute/v2/server.py) in
        U(https://opendev.org/openstack/openstacksdk/) and consult variable
        C(_query_mapping).
    type: dict
  type:
    description:
      - Typename of the resource.
      - Examples are C(ip), C(network), C(router) or C(server).
      - "I(type) must be a C(lowercase) name of a openstacksdk resource class.
         Resource classes are defined in openstacksdk's service folders. For
         example, visit U(https://opendev.org/openstack/openstacksdk), change
         to C(openstack) directory, change to any service directory such as
         C(compute), choose a api version directory such as C(v2) and find all
         available resource classes such as C(Server) inside C(*.py) files."
    required: true
    type: str
notes:
  - "This module does not support all OpenStack cloud resources. Resource
     handling must follow openstacksdk's CRUD structure using and providing
     a C(<service>.<type>s) function. The module will fail if this function
     cannot be found."
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
resources:
  description: Dictionary describing the identified OpenStack cloud resources.
  returned: always
  type: list
  elements: dict
'''

EXAMPLES = r'''
- name: List images
  openstack.cloud.resources:
    cloud: devstack-admin
    service: image
    type: image
  register: images

- name: Identify CirrOS image id
  set_fact:
    image_id: "{{
      images.resources|community.general.json_query(query)|first }}"
  vars:
    query: "[?starts_with(name, 'cirros')].id"

- name: List compute flavors
  openstack.cloud.resources:
    cloud: devstack-admin
    service: compute
    type: flavor
  register: flavors

- name: Identify m1.tiny flavor id
  set_fact:
    flavor_id: "{{
      flavors.resources|community.general.json_query(query)|first }}"
  vars:
    query: "[?name == 'm1.tiny'].id"

- name: List public network
  openstack.cloud.resources:
    cloud: devstack-admin
    service: network
    type: network
    parameters:
      name: public
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class ResourcesModule(OpenStackModule):
    argument_spec = dict(
        parameters=dict(type='dict'),
        service=dict(required=True),
        type=dict(required=True),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        service_name = self.params['service']
        type_name = self.params['type']

        session = getattr(self.conn, service_name)
        list_function = getattr(session, '{0}s'.format(type_name))

        parameters = self.params['parameters']
        resources = \
            list_function(**parameters) if parameters else list_function()

        self.exit_json(
            changed=False,
            resources=[r.to_dict(computed=False) for r in resources])


def main():
    module = ResourcesModule()
    module()


if __name__ == '__main__':
    main()
