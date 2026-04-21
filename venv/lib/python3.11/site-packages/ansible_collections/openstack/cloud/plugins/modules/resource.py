#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Jakob Meng, <jakobmeng@web.de>
# Copyright (c) 2023 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: resource
short_description: Manage a OpenStack cloud resource
author: OpenStack Ansible SIG
description:
  - Create, update and delete a OpenStack cloud resource.
options:
  attributes:
    description:
      - "Resource attributes which are defined in openstacksdk's resource
         classes."
      - I(attributes) is a set of key-value pairs where each key is a attribute
        name such as C(id) and value holds its corresponding attribute value
        such C(ddad2d86-02a6-444d-80ae-1cc2fb023784).
      - Define attribute keys C(id) or C(name) or any set of attribute keys
        which uniquely identify a resource. This module fails if multiple
        resources match the given set of attributes.
      - For a complete list of attributes open any resource class inside
        openstacksdk such as file C(openstack/compute/v2/server.py) in
        U(https://opendev.org/openstack/openstacksdk/) for server attributes.
    required: true
    type: dict
  non_updateable_attributes:
    description:
      - List of attribute names which cannot be updated.
      - When I(non_updateable_attributes) is not specified, then all attributes
        in I(attributes) will be compared to an existing resource during
        updates.
      - When both I(updateable_attributes) and I(non_updateable_attributes) are
        specified, then only attributes which are listed in
        I(updateable_attributes) but not in I(non_updateable_attributes) will
        will be considered during updates.
    type: list
    elements: str
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
  state:
    description:
      - Whether the resource should be C(present) or C(absent).
    choices: ['present', 'absent']
    default: present
    type: str
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
  updateable_attributes:
    description:
      - List of attribute names which can be updated.
      - When I(updateable_attributes) is not specified, then all attributes
        in I(attributes) will be compared to an existing resource during
        updates.
      - When both I(updateable_attributes) and I(non_updateable_attributes) are
        specified, then only attributes which are listed in
        I(updateable_attributes) but not in I(non_updateable_attributes) will
        will be considered during updates.
    type: list
    elements: str
  wait:
    description:
      - Whether Ansible should wait until the resource has reached its target
        I(state).
      - Only a subset of OpenStack resources report a status. Resources which
        do not support status processing will block indefinitely if I(wait) is
        set to C(true).
    type: bool
    default: false
notes:
  - "This module does not support all OpenStack cloud resources. Resource
     handling must follow openstacksdk's CRUD structure using and providing
     C(<service>.<type>s), C(<service>.find_<type>),
     C(<service>.create_<type>), C(<service>.update_<type>) and
     C(<service>.delete_<type>) functions. The module will fail before
     applying any changes if these functions cannot be found."
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
resource:
  description: Dictionary describing the identified (and possibly modified)
               OpenStack cloud resource.
  returned: On success when I(state) is C(present).
  type: dict
'''

EXAMPLES = r'''
- name: Create external network
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: network
    attributes:
      name: ansible_network_external
      is_router_external: true
    wait: true
  register: network_external

- name: Create external subnet
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: subnet
    attributes:
      cidr: 10.6.6.0/24
      ip_version: 4
      name: ansible_external_subnet
      network_id: "{{ network_external.resource.id }}"
  register: subnet_external

- name: Create external port
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: port
    attributes:
      name: ansible_port_external
      network_id: "{{ network_external.resource.id }}"
      fixed_ips:
        - ip_address: 10.6.6.50
    non_updateable_attributes:
      - fixed_ips

- name: Create internal network
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: network
    attributes:
      name: ansible_network_internal
      is_router_external: false
    wait: true
  register: network_internal

- name: Create internal subnet
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: subnet
    attributes:
      cidr: 10.7.7.0/24
      ip_version: 4
      name: ansible_internal_subnet
      network_id: "{{ network_internal.resource.id }}"
  register: subnet_internal

- name: Create internal port
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: port
    attributes:
      name: ansible_port_internal
      network_id: "{{ network_internal.resource.id }}"
      fixed_ips:
        - ip_address: 10.7.7.100
          subnet_id: "{{ subnet_internal.resource.id }}"
  register: port_internal

- name: Create router
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: router
    attributes:
      name: ansible_router
      external_gateway_info:
        enable_snat: true
        external_fixed_ips:
          - ip_address: 10.6.6.10
            subnet_id: "{{ subnet_external.resource.id }}"
        network_id: "{{ network_external.resource.id }}"
    wait: true

- name: Attach router to internal subnet
  openstack.cloud.router:
    cloud: devstack-admin
    name: ansible_router
    network: "{{ network_external.resource.id }}"
    external_fixed_ips:
      - ip: 10.6.6.10
        subnet: "{{ subnet_external.resource.id }}"
    interfaces:
      - net: "{{ network_internal.resource.id }}"
        subnet: "{{ subnet_internal.resource.id }}"
        portip: 10.7.7.1

- name: Create floating ip address
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: ip
    attributes:
      name: 10.6.6.150
      floating_ip_address: 10.6.6.150
      floating_network_id: "{{ network_external.resource.id }}"
      port_id: "{{ port_internal.resource.id }}"
  register: ip

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

- name: Create server
  openstack.cloud.resource:
    cloud: devstack-admin
    service: compute
    type: server
    attributes:
      name: ansible_server
      image_id: "{{ image_id }}"
      flavor_id: "{{ flavor_id }}"
      networks:
        - uuid: "{{ network_internal.resource.id }}"
          port: "{{ port_internal.resource.id }}"
    non_updateable_attributes:
      - name
      - image_id
      - flavor_id
      - networks
    wait: true

- name: Detach floating ip address
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: ip
    attributes:
      floating_ip_address: 10.6.6.150
      port_id: !!null

- name: Delete server
  openstack.cloud.resource:
    cloud: devstack-admin
    service: compute
    type: server
    attributes:
      name: ansible_server
    state: absent
    wait: true

- name: Delete floating ip address
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: ip
    attributes:
      floating_ip_address: 10.6.6.150
    state: absent

- name: Detach router from internal subnet
  openstack.cloud.router:
    cloud: devstack-admin
    name: ansible_router
    network: "{{ network_external.resource.id }}"
    external_fixed_ips:
      - ip: 10.6.6.10
        subnet: "{{ subnet_external.resource.id }}"
    interfaces: []

- name: Delete router
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: router
    attributes:
      name: ansible_router
    state: absent
    wait: true

- name: Delete internal port
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: port
    attributes:
      name: ansible_port_internal
    state: absent

- name: Delete internal subnet
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: subnet
    attributes:
      name: ansible_internal_subnet
    state: absent

- name: Delete internal network
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: network
    attributes:
      name: ansible_network_internal
    state: absent
    wait: true

- name: Delete external port
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: port
    attributes:
      name: ansible_port_external
    state: absent

- name: Delete external subnet
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: subnet
    attributes:
      name: ansible_external_subnet
    state: absent

- name: Delete external network
  openstack.cloud.resource:
    cloud: devstack-admin
    service: network
    type: network
    attributes:
      name: ansible_network_external
    state: absent
    wait: true
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule
from ansible_collections.openstack.cloud.plugins.module_utils.resource import StateMachine


class ResourceModule(OpenStackModule):
    argument_spec = dict(
        attributes=dict(required=True, type='dict'),
        non_updateable_attributes=dict(type='list', elements='str'),
        service=dict(required=True),
        state=dict(default='present', choices=['absent', 'present']),
        type=dict(required=True),
        updateable_attributes=dict(type='list', elements='str'),
        wait=dict(default=False, type='bool'),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        service_name = self.params['service']
        type_name = self.params['type']

        sm = StateMachine(connection=self.conn,
                          service_name=service_name,
                          type_name=type_name,
                          sdk=self.sdk)

        kwargs = dict((k, self.params[k])
                      for k in ['attributes', 'non_updateable_attributes',
                                'state', 'timeout', 'wait',
                                'updateable_attributes'])

        resource, is_changed = sm(check_mode=self.ansible.check_mode, **kwargs)

        if resource is None:
            self.exit_json(changed=is_changed)
        else:
            self.exit_json(changed=is_changed,
                           resource=resource.to_dict(computed=False))


def main():
    module = ResourceModule()
    module()


if __name__ == '__main__':
    main()
