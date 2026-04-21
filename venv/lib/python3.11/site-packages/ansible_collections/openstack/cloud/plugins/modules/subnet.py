#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013, Benno Joy <benno@ansible.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: subnet
short_description: Add/Remove subnet to an OpenStack network
author: OpenStack Ansible SIG
description:
   - Add or Remove a subnet to an OpenStack network
options:
    state:
        description:
            - Indicate desired state of the resource
        choices: ['present', 'absent']
        default: present
        type: str
    allocation_pool_start:
        description:
            - From the subnet pool the starting address from which the IP
              should be allocated.
        type: str
    allocation_pool_end:
        description:
            - From the subnet pool the last IP that should be assigned to the
              virtual machines.
        type: str
    allocation_pools:
        description:
            - List of allocation pools to assign to the subnet. Each element
              consists of a 'start' and 'end' value.
        type: list
        elements: dict
    cidr:
        description:
            - The CIDR representation of the subnet that should be assigned to
              the subnet. Required when I(state) is 'present' and a subnetpool
              is not specified.
        type: str
    description:
        description:
            - Description of the subnet
        type: str
    disable_gateway_ip:
        description:
            - The gateway IP would not be assigned for this subnet
        type: bool
        aliases: ['no_gateway_ip']
        default: 'false'
    dns_nameservers:
        description:
            - List of DNS nameservers for this subnet.
        type: list
        elements: str
    extra_attrs:
        description:
            - Dictionary with extra key/value pairs passed to the API
        required: false
        aliases: ['extra_specs']
        default: {}
        type: dict
    host_routes:
        description:
            - A list of host route dictionaries for the subnet.
        type: list
        elements: dict
        suboptions:
            destination:
                description: The destination network (CIDR).
                type: str
                required: true
            nexthop:
                description: The next hop (aka gateway) for the I(destination).
                type: str
                required: true
    gateway_ip:
        description:
            - The ip that would be assigned to the gateway for this subnet
        type: str
    ip_version:
        description:
            - The IP version of the subnet 4 or 6
        default: 4
        type: int
        choices: [4, 6]
    is_dhcp_enabled:
        description:
            - Whether DHCP should be enabled for this subnet.
        type: bool
        aliases: ['enable_dhcp']
        default: 'true'
    ipv6_ra_mode:
        description:
            - IPv6 router advertisement mode
        choices: ['dhcpv6-stateful', 'dhcpv6-stateless', 'slaac']
        type: str
    ipv6_address_mode:
        description:
            - IPv6 address mode
        choices: ['dhcpv6-stateful', 'dhcpv6-stateless', 'slaac']
        type: str
    name:
        description:
            - The name of the subnet that should be created. Although Neutron
              allows for non-unique subnet names, this module enforces subnet
              name uniqueness.
        required: true
        type: str
    network:
        description:
            - Name or id of the network to which the subnet should be attached
            - Required when I(state) is 'present'
        aliases: ['network_name']
        type: str
    project:
        description:
            - Project name or ID containing the subnet (name admin-only)
        type: str
    prefix_length:
        description:
            - The prefix length to use for subnet allocation from a subnet pool
        type: str
    use_default_subnet_pool:
        description:
            - Use the default subnetpool for I(ip_version) to obtain a CIDR.
        type: bool
        aliases: ['use_default_subnetpool']
    subnet_pool:
        description:
            - The subnet pool name or ID from which to obtain a CIDR
        type: str
        required: false
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
# Create a new (or update an existing) subnet on the specified network
- openstack.cloud.subnet:
    state: present
    network_name: network1
    name: net1subnet
    cidr: 192.168.0.0/24
    dns_nameservers:
       - 8.8.8.7
       - 8.8.8.8
    host_routes:
       - destination: 0.0.0.0/0
         nexthop: 12.34.56.78
       - destination: 192.168.0.0/24
         nexthop: 192.168.0.1

# Delete a subnet
- openstack.cloud.subnet:
    state: absent
    name: net1subnet

# Create an ipv6 stateless subnet
- openstack.cloud.subnet:
    state: present
    name: intv6
    network_name: internal
    ip_version: 6
    cidr: 2db8:1::/64
    dns_nameservers:
        - 2001:4860:4860::8888
        - 2001:4860:4860::8844
    ipv6_ra_mode: dhcpv6-stateless
    ipv6_address_mode: dhcpv6-stateless
'''

RETURN = '''
id:
    description: Id of subnet
    returned: On success when subnet exists.
    type: str
subnet:
    description: Dictionary describing the subnet.
    returned: On success when subnet exists.
    type: dict
    contains:
        allocation_pools:
            description: Allocation pools associated with this subnet.
            returned: success
            type: list
            elements: dict
        cidr:
            description: Subnet's CIDR.
            returned: success
            type: str
        created_at:
            description: Created at timestamp
            type: str
        description:
            description: Description
            type: str
        dns_nameservers:
            description: DNS name servers for this subnet.
            returned: success
            type: list
            elements: str
        dns_publish_fixed_ip:
            description: Whether to publish DNS records for fixed IPs.
            returned: success
            type: bool
        gateway_ip:
            description: Subnet's gateway ip.
            returned: success
            type: str
        host_routes:
            description: A list of host routes.
            returned: success
            type: str
        id:
            description: Unique UUID.
            returned: success
            type: str
        ip_version:
            description: IP version for this subnet.
            returned: success
            type: int
        ipv6_address_mode:
            description: |
                The IPv6 address modes which are 'dhcpv6-stateful',
                'dhcpv6-stateless' or 'slaac'.
            returned: success
            type: str
        ipv6_ra_mode:
            description: |
                The IPv6 router advertisements modes which can be 'slaac',
                'dhcpv6-stateful', 'dhcpv6-stateless'.
            returned: success
            type: str
        is_dhcp_enabled:
            description: DHCP enable flag for this subnet.
            returned: success
            type: bool
        name:
            description: Name given to the subnet.
            returned: success
            type: str
        network_id:
            description: Network ID this subnet belongs in.
            returned: success
            type: str
        prefix_length:
            description: |
                The prefix length to use for subnet allocation from a subnet
                pool.
            returned: success
            type: str
        project_id:
            description: Project id associated with this subnet.
            returned: success
            type: str
        revision_number:
            description: Revision number of the resource
            returned: success
            type: int
        segment_id:
            description: The ID of the segment this subnet is associated with.
            returned: success
            type: str
        service_types:
            description: Service types for this subnet
            returned: success
            type: list
        subnet_pool_id:
            description: The subnet pool ID from which to obtain a CIDR.
            returned: success
            type: str
        tags:
            description: Tags
            type: str
        updated_at:
            description: Timestamp when the subnet was last updated.
            returned: success
            type: str
        use_default_subnet_pool:
            description: |
                Whether to use the default subnet pool to obtain a CIDR.
            returned: success
            type: bool
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class SubnetModule(OpenStackModule):
    ipv6_mode_choices = ['dhcpv6-stateful', 'dhcpv6-stateless', 'slaac']
    argument_spec = dict(
        name=dict(required=True),
        network=dict(aliases=['network_name']),
        cidr=dict(),
        description=dict(),
        ip_version=dict(type='int', default=4, choices=[4, 6]),
        is_dhcp_enabled=dict(type='bool', default=True,
                             aliases=['enable_dhcp']),
        gateway_ip=dict(),
        disable_gateway_ip=dict(
            type='bool', default=False, aliases=['no_gateway_ip']),
        dns_nameservers=dict(type='list', elements='str'),
        allocation_pool_start=dict(),
        allocation_pool_end=dict(),
        allocation_pools=dict(type='list', elements='dict'),
        host_routes=dict(type='list', elements='dict'),
        ipv6_ra_mode=dict(choices=ipv6_mode_choices),
        ipv6_address_mode=dict(choices=ipv6_mode_choices),
        subnet_pool=dict(),
        prefix_length=dict(),
        use_default_subnet_pool=dict(
            type='bool', aliases=['use_default_subnetpool']),
        extra_attrs=dict(type='dict', default=dict(), aliases=['extra_specs']),
        state=dict(default='present',
                   choices=['absent', 'present']),
        project=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True,
        required_together=[['allocation_pool_end', 'allocation_pool_start']],
        required_if=[
            ('state', 'present', ('network',)),
            ('state', 'present',
             ('cidr', 'use_default_subnet_pool', 'subnet_pool'), True),
        ],
        mutually_exclusive=[
            ('use_default_subnet_pool', 'subnet_pool'),
            ('allocation_pool_start', 'allocation_pools'),
            ('allocation_pool_end', 'allocation_pools')
        ]
    )

    # resource attributes obtainable directly from params
    attr_params = ('cidr', 'description',
                   'dns_nameservers', 'gateway_ip', 'host_routes',
                   'ip_version', 'ipv6_address_mode', 'ipv6_ra_mode',
                   'is_dhcp_enabled', 'name', 'prefix_length',
                   'use_default_subnet_pool',)

    def _validate_update(self, subnet, update):
        """ Check for differences in non-updatable values """
        # Ref.: https://docs.openstack.org/api-ref/network/v2/index.html#update-subnet
        for attr in ('cidr', 'ip_version', 'ipv6_ra_mode', 'ipv6_address_mode',
                     'prefix_length', 'use_default_subnet_pool'):
            if attr in update and update[attr] != subnet[attr]:
                self.fail_json(
                    msg='Cannot update {0} in existing subnet'.format(attr))

    def _system_state_change(self, subnet, network, project, subnet_pool):
        state = self.params['state']
        if state == 'absent':
            return subnet is not None
        # else state is present
        if not subnet:
            return True
        params = self._build_params(network, project, subnet_pool)
        updates = self._build_updates(subnet, params)
        self._validate_update(subnet, updates)
        return bool(updates)

    def _build_pool(self):
        pool_start = self.params['allocation_pool_start']
        pool_end = self.params['allocation_pool_end']
        if pool_start:
            return [dict(start=pool_start, end=pool_end)]
        return None

    def _build_params(self, network, project, subnet_pool):
        params = {attr: self.params[attr] for attr in self.attr_params}
        params['network_id'] = network.id
        if project:
            params['project_id'] = project.id
        if subnet_pool:
            params['subnet_pool_id'] = subnet_pool.id
        if self.params['allocation_pool_start']:
            params['allocation_pools'] = self._build_pool()
        else:
            params['allocation_pools'] = self.params['allocation_pools']
        params = self._add_extra_attrs(params)
        params = {k: v for k, v in params.items() if v is not None}
        if self.params['disable_gateway_ip']:
            params['gateway_ip'] = None
        return params

    def _build_updates(self, subnet, params):
        # Sort lists before doing comparisons comparisons
        if 'dns_nameservers' in params:
            params['dns_nameservers'].sort()
            subnet['dns_nameservers'].sort()

        if 'host_routes' in params:
            params['host_routes'].sort(key=lambda r: sorted(r.items()))
            subnet['host_routes'].sort(key=lambda r: sorted(r.items()))

        if 'allocation_pools' in params:
            params['allocation_pools'].sort(key=lambda r: sorted(r.items()))
            subnet['allocation_pools'].sort(key=lambda r: sorted(r.items()))

        updates = {k: params[k] for k in params if params[k] != subnet[k]}
        if self.params['disable_gateway_ip'] and subnet.gateway_ip:
            updates['gateway_ip'] = None
        return updates

    def _add_extra_attrs(self, params):
        duplicates = set(self.params['extra_attrs']) & set(params)
        if duplicates:
            self.fail_json(msg='Duplicate key(s) {0} in extra_specs'
                           .format(list(duplicates)))
        params.update(self.params['extra_attrs'])
        return params

    def run(self):
        state = self.params['state']
        network_name_or_id = self.params['network']
        project_name_or_id = self.params['project']
        subnet_pool_name_or_id = self.params['subnet_pool']
        subnet_name = self.params['name']
        gateway_ip = self.params['gateway_ip']
        disable_gateway_ip = self.params['disable_gateway_ip']

        # fail early if incompatible options have been specified
        if disable_gateway_ip and gateway_ip:
            self.fail_json(msg='no_gateway_ip is not allowed with gateway_ip')

        subnet_pool_filters = {}
        filters = {}

        project = None
        if project_name_or_id:
            project = self.conn.identity.find_project(project_name_or_id,
                                                      ignore_missing=False)
            subnet_pool_filters['project_id'] = project.id
            filters['project_id'] = project.id

        network = None
        if network_name_or_id:
            # At this point filters can only contain project_id
            network = self.conn.network.find_network(network_name_or_id,
                                                     ignore_missing=False,
                                                     **filters)
            filters['network_id'] = network.id

        subnet_pool = None
        if subnet_pool_name_or_id:
            subnet_pool = self.conn.network.find_subnet_pool(
                subnet_pool_name_or_id,
                ignore_missing=False,
                **subnet_pool_filters)
            filters['subnet_pool_id'] = subnet_pool.id

        subnet = self.conn.network.find_subnet(subnet_name, **filters)

        if self.ansible.check_mode:
            self.exit_json(changed=self._system_state_change(
                subnet, network, project, subnet_pool))

        changed = False
        if state == 'present':
            params = self._build_params(network, project, subnet_pool)
            if subnet is None:
                subnet = self.conn.network.create_subnet(**params)
                changed = True
            else:
                updates = self._build_updates(subnet, params)
                if updates:
                    self._validate_update(subnet, updates)
                    subnet = self.conn.network.update_subnet(subnet, **updates)
                    changed = True
            self.exit_json(changed=changed, subnet=subnet, id=subnet.id)
        elif state == 'absent' and subnet is not None:
            self.conn.network.delete_subnet(subnet)
            changed = True
        self.exit_json(changed=changed)


def main():
    module = SubnetModule()
    module()


if __name__ == '__main__':
    main()
