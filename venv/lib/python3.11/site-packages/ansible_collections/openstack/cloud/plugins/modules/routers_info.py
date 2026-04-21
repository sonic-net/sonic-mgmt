#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019, Bram Verschueren <verschueren.bram@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: routers_info
short_description: Retrieve information about one or more OpenStack routers.
author: OpenStack Ansible SIG
description:
    - Retrieve information about one or more routers from OpenStack.
options:
   name:
     description:
        - Name or ID of the router
     required: false
     type: str
   filters:
     description:
        - A dictionary of meta data to use for further filtering. Elements of
          this dictionary may be additional dictionaries.
     required: false
     type: dict
     default: {}
     suboptions:
       project_id:
         description:
           - Filter the list result by the ID of the project that owns the
             resource.
         type: str
         aliases:
           - tenant_id
       name:
         description:
           - Filter the list result by the human-readable name of the resource.
         type: str
       description:
         description:
           - Filter the list result by the human-readable description of the
             resource.
         type: str
       is_admin_state_up:
         description:
           - Filter the list result by the administrative state of the
             resource, which is up (true) or down (false).
         type: bool
       revision_number:
         description:
           - Filter the list result by the revision number of the resource.
         type: int
       tags:
         description:
           - A list of tags to filter the list result by. Resources that match
             all tags in this list will be returned.
         type: list
         elements: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
- name: Gather information about routers
  openstack.cloud.routers_info:
    auth:
      auth_url: https://identity.example.com
      username: user
      password: password
      project_name: someproject
  register: result

- name: Show openstack routers
  debug:
    msg: "{{ result.routers }}"

- name: Gather information about a router by name
  openstack.cloud.routers_info:
    auth:
      auth_url: https://identity.example.com
      username: user
      password: password
      project_name: someproject
    name: router1
  register: result

- name: Show openstack routers
  debug:
    msg: "{{ result.routers }}"

- name: Gather information about a router with filter
  openstack.cloud.routers_info:
    auth:
      auth_url: https://identity.example.com
      username: user
      password: password
      project_name: someproject
    filters:
      is_admin_state_up: True
  register: result

- name: Show openstack routers
  debug:
    msg: "{{ result.routers }}"

- name: List all routers
  openstack.cloud.routers_info:
     cloud: devstack
  register: routers

- name: List ports of first router
  openstack.cloud.port_info:
    cloud: devstack
    filters:
      device_id: "{{ routers.routers.0.id }}"
  register: ports

- name: Show first router's fixed ips
  debug:
    msg: "{{ ports.ports
        |rejectattr('device_owner', 'equalto', 'network:router_gateway')
        |sum(attribute='fixed_ips', start=[])
        |map(attribute='ip_address')
        |sort|list }}"

- name: List ports of all routers
  loop: "{{ routers.routers }}"
  openstack.cloud.port_info:
    cloud: devstack
    filters:
      device_id: "{{ item['id'] }}"
  register: ports

- name: Transform ports for interfaces_info entries
  loop: "{{ ports.results|map(attribute='ports')|list }}"
  set_fact:
    interfaces_info: |-
        {% for port in item %}
        {% if port.device_owner != "network:router_gateway" %}
        {% for fixed_ip in port['fixed_ips'] %}
        - port_id: {{ port.id }}
          ip_address: {{ fixed_ip.ip_address }}
          subnet_id: {{ fixed_ip.subnet_id }}
        {% endfor %}
        {% endif %}
        {% endfor %}
  register: interfaces

- name: Combine router and interfaces_info entries
  loop: "{{
      routers.routers|zip(interfaces.results|map(attribute='ansible_facts'))|list
  }}"
  set_fact:
    # underscore prefix to prevent overwriting facts outside of loop
    _router: "{{
        item.0|combine({'interfaces_info': item.1.interfaces_info|from_yaml})
    }}"
  register: routers

- name: Remove set_fact artifacts from routers
  set_fact:
    routers: "{{ {
        'routers': routers.results|map(attribute='ansible_facts._router')|list
    } }}"

- debug: var=routers
'''

RETURN = '''
routers:
    description: has all the openstack information about the routers
    returned: always, but can be null
    type: list
    elements: dict
    contains:
        availability_zones:
            description: Availability zones
            returned: success
            type: list
        availability_zone_hints:
            description: Availability zone hints
            returned: success
            type: list
        created_at:
            description: Date and time when the router was created
            returned: success
            type: str
        description:
            description: Description notes of the router
            returned: success
            type: str
        external_gateway_info:
            description: The external gateway information of the router.
            returned: success
            type: dict
        flavor_id:
            description: ID of the flavor of the router
            returned: success
            type: str
        id:
            description: Unique UUID.
            returned: success
            type: str
        is_admin_state_up:
            description: Network administrative state
            returned: success
            type: bool
        is_distributed:
            description: Indicates a distributed router.
            returned: success
            type: bool
        is_ha:
            description: Indicates a highly-available router.
            returned: success
            type: bool
        name:
            description: Name given to the router.
            returned: success
            type: str
        project_id:
            description: Project id associated with this router.
            returned: success
            type: str
        revision_number:
            description: Revision number
            returned: success
            type: int
        routes:
            description: The extra routes configuration for L3 router.
            returned: success
            type: list
        status:
            description: Router status.
            returned: success
            type: str
        tags:
            description: List of tags
            returned: success
            type: list
        tenant_id:
            description: Owner tenant ID
            returned: success
            type: str
        updated_at:
            description: Date of last update on the router
            returned: success
            type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class RouterInfoModule(OpenStackModule):

    argument_spec = dict(
        name=dict(),
        filters=dict(type='dict', default={})
    )
    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        routers = [
            router.to_dict(computed=False)
            for router in self.conn.search_routers(
                name_or_id=self.params['name'],
                filters=self.params['filters'])]
        self.exit(changed=False, routers=routers)


def main():
    module = RouterInfoModule()
    module()


if __name__ == '__main__':
    main()
