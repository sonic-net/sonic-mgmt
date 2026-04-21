#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: subnets_info
short_description: Retrieve information about one or more OpenStack subnets.
author: OpenStack Ansible SIG
description:
    - Retrieve information about one or more subnets from OpenStack.
options:
   name:
     description:
        - Name or ID of the subnet.
        - Alias 'subnet' added in version 2.8.
     required: false
     aliases: ['subnet']
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
- name: Gather information about previously created subnets
  openstack.cloud.subnets_info:
    auth:
      auth_url: https://identity.example.com
      username: user
      password: password
      project_name: someproject
  register: result

- name: Show openstack subnets
  debug:
    msg: "{{ result.subnets }}"

- name: Gather information about a previously created subnet by name
  openstack.cloud.subnets_info:
    auth:
      auth_url: https://identity.example.com
      username: user
      password: password
      project_name: someproject
    name: subnet1
  register: result

- name: Show openstack subnets
  debug:
    msg: "{{ result.subnets }}"

- name: Gather information about a previously created subnet with filter
  # Note: name and filters parameters are not mutually exclusive
  openstack.cloud.subnets_info:
    auth:
      auth_url: https://identity.example.com
      username: user
      password: password
      project_name: someproject
    filters:
      project_id: 55e2ce24b2a245b09f181bf025724cbe
  register: result

- name: Show openstack subnets
  debug:
    msg: "{{ result.subnets }}"
'''

RETURN = '''
subnets:
    description: has all the openstack information about the subnets
    returned: always, but can be empty list
    type: list
    elements: dict
    contains:
        id:
            description: The ID of the subnet.
            type: str
        name:
            description: Name given to the subnet.
            type: str
        description:
            description: Description of the subnet.
            type: str
        network_id:
            description: Network ID this subnet belongs in.
            type: str
        cidr:
            description: Subnet's CIDR.
            type: str
        gateway_ip:
            description: Subnet's gateway ip.
            type: str
        is_dhcp_enabled:
            description: Is DHCP enabled.
            type: bool
        ip_version:
            description: IP version for this subnet.
            type: int
        dns_nameservers:
            description: DNS name servers for this subnet.
            type: list
            elements: str
        allocation_pools:
            description: Allocation pools associated with this subnet.
            type: list
            elements: dict
        created_at:
            description: Date and time when the resource was created.
            type: str
        updated_at:
            description: Date and time when the resource was updated.
            type: str
        dns_publish_fixed_ip:
            description: Whether to publish DNS records for IPs from this subnet.
            type: str
        host_routes:
            description: Additional routes for the subnet.
            type: list
            elements: dict
        ipv6_address_mode:
            description: The IPv6 address modes specifies mechanisms for assigning IP addresses.
            type: str
        ipv6_ra_mode:
            description: The IPv6 router advertisement specifies whether the networking service should transmit ICMPv6 packets, for a subnet.
            type: str
        project_id:
            description: The ID of the project.
            type: str
        revision_number:
            description: The revision number of the resource.
            type: str
        segment_id:
            description: The ID of a network segment the subnet is associated with.
            type: str
        service_types:
            description: The service types associated with the subnet.
            type: list
            elements: str
        subnet_pool_id:
            description: The ID of the subnet pool associated with the subnet.
            type: str
        tags:
            description: The list of tags on the resource.
            type: list
            elements: str
        prefix_length:
            description: The prefix length to use for subnet allocation from a subnet pool.
            type: str
        use_default_subnet_pool:
            description: Whether to use the default subnet pool to obtain a CIDR.
            type: bool
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class SubnetInfoModule(OpenStackModule):
    argument_spec = dict(
        name=dict(aliases=['subnet']),
        filters=dict(type='dict')
    )
    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        kwargs = {}
        subnets = []
        if self.params['name']:
            kwargs['name'] = self.params['name']
            # Try to get subnet by ID
            try:
                raw = self.conn.network.get_subnet(self.params['name'])
                raw = raw.to_dict(computed=False)
                subnets.append(raw)
                self.exit(changed=False, subnets=subnets)
            except self.sdk.exceptions.ResourceNotFound:
                pass
        if self.params['filters']:
            kwargs.update(self.params['filters'])
        subnets = self.conn.network.subnets(**kwargs)
        subnets = [i.to_dict(computed=False) for i in subnets]
        self.exit(changed=False, subnets=subnets)


def main():
    module = SubnetInfoModule()
    module()


if __name__ == '__main__':
    main()
