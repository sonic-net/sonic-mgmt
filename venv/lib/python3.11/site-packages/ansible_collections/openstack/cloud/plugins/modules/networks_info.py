#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: networks_info
short_description: Retrieve information about one or more OpenStack networks.
author: OpenStack Ansible SIG
description:
    - Retrieve information about one or more networks from OpenStack.
options:
   name:
     description:
        - Name or ID of the Network
     required: false
     type: str
   filters:
     description:
        - A dictionary of meta data to use for further filtering.  Elements of
          this dictionary may be additional dictionaries.
     required: false
     type: dict
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
- name: Gather information about previously created networks
  openstack.cloud.networks_info:
    auth:
      auth_url: https://identity.example.com
      username: user
      password: password
      project_name: someproject
  register: result

- name: Show openstack networks
  debug:
    msg: "{{ result.networks }}"

- name: Gather information about a previously created network by name
  openstack.cloud.networks_info:
    auth:
      auth_url: https://identity.example.com
      username: user
      password: password
      project_name: someproject
    name:  network1
  register: result

- name: Show openstack networks
  debug:
    msg: "{{ result.networks }}"

- name: Gather information about a previously created network with filter
  # Note: name and filters parameters are Not mutually exclusive
  openstack.cloud.networks_info:
    auth:
      auth_url: https://identity.example.com
      username: user
      password: password
      project_name: someproject
    filters:
      tenant_id: 55e2ce24b2a245b09f181bf025724cbe
      subnets:
        - 057d4bdf-6d4d-4728-bb0f-5ac45a6f7400
        - 443d4dc0-91d4-4998-b21c-357d10433483
  register: result

- name: Show openstack networks
  debug:
    msg: "{{ result.networks }}"
'''

RETURN = '''
networks:
    description: has all the openstack information about the networks
    returned: always, but can be empty list
    type: list
    elements: dict
    contains:
        availability_zone_hints:
            description: Availability zone hints
            type: str
        availability_zones:
            description: Availability zones
            type: str
        created_at:
            description: Created at timestamp
            type: str
        description:
            description: Description
            type: str
        dns_domain:
            description: Dns domain
            type: str
        id:
            description: Id
            type: str
        ipv4_address_scope_id:
            description: Ipv4 address scope id
            type: str
        ipv6_address_scope_id:
            description: Ipv6 address scope id
            type: str
        is_admin_state_up:
            description: Is admin state up
            type: str
        is_default:
            description: Is default
            type: str
        is_port_security_enabled:
            description: Is port security enabled
            type: str
        is_router_external:
            description: Is router external
            type: str
        is_shared:
            description: Is shared
            type: str
        is_vlan_transparent:
            description: Is vlan transparent
            type: str
        mtu:
            description: Mtu
            type: str
        name:
            description: Name
            type: str
        project_id:
            description: Project id
            type: str
        provider_network_type:
            description: Provider network type
            type: str
        provider_physical_network:
            description: Provider physical network
            type: str
        provider_segmentation_id:
            description: Provider segmentation id
            type: str
        qos_policy_id:
            description: Qos policy id
            type: str
        revision_number:
            description: Revision number
            type: str
        segments:
            description: Segments
            type: str
        status:
            description: Status
            type: str
        subnet_ids:
            description: Subnet ids
            type: str
        tags:
            description: Tags
            type: str
        updated_at:
            description: Updated at timestamp
            type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class NetworkInfoModule(OpenStackModule):
    argument_spec = dict(
        name=dict(),
        filters=dict(type='dict')
    )
    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        kwargs = {
            'filters': self.params['filters'],
            'name_or_id': self.params['name']
        }
        networks = self.conn.search_networks(**kwargs)
        networks = [i.to_dict(computed=False) for i in networks]
        self.exit(changed=False, networks=networks)


def main():
    module = NetworkInfoModule()
    module()


if __name__ == '__main__':
    main()
