#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2019 Bernhard Hopfenmüller (ATIX AG)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: host
version_added: 1.0.0
short_description: Manage Hosts
description:
  - Create, update, and delete Hosts
author:
  - "Bernhard Hopfenmueller (@Fobhep) ATIX AG"
options:
  name:
    description:
      - Fully Qualified Domain Name of host
    required: true
    type: str
  hostgroup:
    description:
      - Title of related hostgroup
      - "Example: A child hostgroup I(bar) within a parent hostgroup I(foo) would have the title I(foo/bar)."
    required: false
    type: str
  location:
    description:
      - Name of related location
    required: false
    type: str
  organization:
    description:
      - Name of related organization
    required: false
    type: str
  build:
    description:
      - Whether or not to setup build context for the host
    type: bool
    required: false
  enabled:
    description:
      - Include this host within reporting
    type: bool
    required: false
  managed:
    description:
      - Whether a host is managed or unmanaged.
      - Forced to true when I(build=true)
    type: bool
    required: false
  ip:
    description:
      - IP address of the primary interface of the host.
    type: str
    required: false
  mac:
    description:
      - MAC address of the primary interface of the host.
      - Please include leading zeros and separate nibbles by colons, otherwise the execution will not be idempotent.
      - Example EE:BB:01:02:03:04
    type: str
    required: false
  comment:
    description:
      - Comment about the host.
    type: str
    required: false
  owner:
    description:
      - Owner (user) of the host.
      - Users are looked up by their C(login).
      - Mutually exclusive with I(owner_group).
    type: str
    required: false
  owner_group:
    description:
      - Owner (user group) of the host.
      - Mutually exclusive with I(owner).
    type: str
    required: false
  provision_method:
    description:
      - The method used to provision the host.
      - I(provision_method=bootdisk) is only available if the bootdisk plugin is installed.
    choices:
      - 'build'
      - 'image'
      - 'bootdisk'
    type: str
    required: false
  image:
    description:
      - The image to use when I(provision_method=image).
      - The I(compute_resource) parameter is required to find the correct image.
    type: str
    required: false
  compute_attributes:
    description:
      - Additional compute resource specific attributes.
      - When this parameter is set, the module will not be idempotent.
      - When you provide a I(cluster) here and I(compute_resource) is set, the cluster id will be automatically looked up.
    type: dict
    required: false
  interfaces_attributes:
    description:
      - Additional interfaces specific attributes.
    version_added: 1.5.0
    required: false
    type: list
    elements: dict
    suboptions:
      mac:
        description:
          - MAC address of interface. Required for managed interfaces on bare metal.
          - Please include leading zeros and separate nibbles by colons, otherwise the execution will not be idempotent.
          - Example EE:BB:01:02:03:04
          - You need to set one of I(identifier), I(name) or I(mac) to be able to update existing interfaces and make execution idempotent.
        type: str
      ip:
        description:
          - IPv4 address of interface
        type: str
      ip6:
        description:
          - IPv6 address of interface
        type: str
      type:
        description:
          - Interface type.
        type: str
        choices:
          - 'interface'
          - 'bmc'
          - 'bond'
          - 'bridge'
      name:
        description:
          - Interface's DNS name
          - You need to set one of I(identifier), I(name) or I(mac) to be able to update existing interfaces and make execution idempotent.
        type: str
      subnet:
        description:
          - IPv4 Subnet name
        type: str
      subnet6:
        description:
          - IPv6 Subnet name
        type: str
      domain:
        description:
          - Domain name
          - Required for primary interfaces on managed hosts.
        type: str
      identifier:
        description:
          - Device identifier, e.g. eth0 or eth1.1
          - You need to set one of I(identifier), I(name) or I(mac) to be able to update existing interfaces and make execution idempotent.
        type: str
      managed:
        description:
          - Should this interface be managed via DHCP and DNS smart proxy and should it be configured during provisioning?
        type: bool
      primary:
        description:
          - Should this interface be used for constructing the FQDN of the host?
          - Each managed hosts needs to have one primary interface.
        type: bool
      provision:
        description:
          - Should this interface be used for TFTP of PXELinux (or SSH for image-based hosts)?
          - Each managed hosts needs to have one provision interface.
        type: bool
      execution:
        description:
          - Should this interface be used for Remote Execution?
          - Each managed hosts should have one remote execution interface.
        type: bool
      username:
        description:
          - Username for BMC authentication.
          - Only for BMC interfaces.
        type: str
      password:
        description:
          - Password for BMC authentication.
          - Only for BMC interfaces.
        type: str
      provider:
        description:
          - Interface provider, e.g. IPMI.
          - Only for BMC interfaces.
        type: str
        choices:
          - 'IPMI'
          - 'Redfish'
          - 'SSH'
      virtual:
        description:
          - Alias or VLAN device
        type: bool
      tag:
        description:
          - VLAN tag, this attribute has precedence over the subnet VLAN ID.
          - Only for virtual interfaces.
        type: str
      mtu:
        description:
          - MTU, this attribute has precedence over the subnet MTU.
        type: int
      attached_to:
        description:
          - Identifier of the interface to which this interface belongs, e.g. eth1.
          - Only for virtual interfaces.
        type: str
      mode:
        description:
          - Bond mode of the interface.
          - Only for bond interfaces.
        type: str
        choices:
          - 'balance-rr'
          - 'active-backup'
          - 'balance-xor'
          - 'broadcast'
          - '802.3ad'
          - 'balance-tlb'
          - 'balance-alb'
      attached_devices:
        description:
          - Identifiers of attached interfaces, e.g. ['eth1', 'eth2'].
          - For bond interfaces those are the slaves.
          - Only for bond and bridges interfaces.
        type: list
        elements: str
      bond_options:
        description:
          - Space separated options, e.g. miimon=100.
          - Only for bond interfaces.
        type: str
      compute_attributes:
        description:
          - Additional compute resource specific attributes for the interface.
          - When this parameter is set, the module will not be idempotent.
          - When you provide a I(network) here and I(compute_resource) is set, the network id will be automatically looked up.
          - On oVirt/RHV I(cluster) is required in the hosts I(compute_attributes) for the lookup to work.
        type: dict
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.entity_state
  - theforeman.foreman.foreman.host_options
  - theforeman.foreman.foreman.nested_parameters
  - theforeman.foreman.foreman.operatingsystem
'''

EXAMPLES = '''
- name: "Create a host"
  theforeman.foreman.host:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "new_host"
    hostgroup: my_hostgroup
    state: present

- name: "Create a host with build context"
  theforeman.foreman.host:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "new_host"
    hostgroup: my_hostgroup
    build: true
    state: present

- name: "Create an unmanaged host"
  theforeman.foreman.host:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "new_host"
    managed: false
    state: present

- name: "Create a VM with 2 CPUs and 4GB RAM"
  theforeman.foreman.host:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "new_host"
    compute_attributes:
      cpus: 2
      memory_mb: 4096
    state: present

- name: "Create a VM and start it after creation"
  theforeman.foreman.host:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "new_host"
    compute_attributes:
      start: "1"
    state: present

- name: "Create a VM on specific ovirt network"
  theforeman.foreman.host:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "new_host"
    interfaces_attributes:
      - type: "interface"
        compute_attributes:
          name: "nic1"
          network: "969efbe6-f9e0-4383-a19a-a7ee65ad5007"
          interface: "virtio"
    state: present

- name: "Create a VM with 2 NICs on specific ovirt networks"
  theforeman.foreman.host:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "new_host"
    interfaces_attributes:
      - type: "interface"
        primary: true
        compute_attributes:
          name: "nic1"
          network: "969efbe6-f9e0-4383-a19a-a7ee65ad5007"
          interface: "virtio"
      - type: "interface"
        name: "new_host_nic2"
        managed: true
        compute_attributes:
          name: "nic2"
          network: "969efbe6-f9e0-4383-a19a-a7ee65ad5008"
          interface: "e1000"
    state: present

- name: "Delete a host"
  theforeman.foreman.host:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "new_host"
    state: absent
'''

RETURN = '''
entity:
  description: Final state of the affected entities grouped by their type.
  returned: success
  type: dict
  contains:
    hosts:
      description: List of hosts.
      type: list
      elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import (
    ensure_puppetclasses,
    interfaces_spec,
    ForemanEntityAnsibleModule,
    HostMixin,
)


def ensure_host_interfaces(module, entity, interfaces):
    scope = {'host_id': entity['id']}

    current_interfaces = module.list_resource('interfaces', params=scope)
    current_interfaces_ids = {x['id'] for x in current_interfaces}
    expected_interfaces_ids = set()

    for interface in interfaces:
        if 1 == len(current_interfaces) == len(interfaces):
            existing_interface = current_interfaces[0]
        else:
            for possible_identifier in ['identifier', 'name', 'mac']:
                if possible_identifier in interface:
                    unique_identifier = possible_identifier
                    break
            else:
                unique_identifier = None
                warning_msg = "The provided interface definition has no unique identifier and thus cannot be matched against existing interfaces. " \
                    "This will always create a new interface and might not be the desired behaviour."
                module.warn(warning_msg)

            existing_interface = next((x for x in current_interfaces if unique_identifier and x.get(unique_identifier) == interface[unique_identifier]), None)

        if 'mac' in interface:
            interface['mac'] = interface['mac'].lower()

        # workaround for https://projects.theforeman.org/issues/31390
        if existing_interface is not None and 'attached_devices' in existing_interface:
            existing_interface['attached_devices'] = existing_interface['attached_devices'].split(',')

        updated_interface = (existing_interface or {}).copy()
        updated_interface.update(interface)

        module.ensure_entity('interfaces', updated_interface, existing_interface, params=scope, state='present',
                             foreman_spec=module.foreman_spec['interfaces_attributes']['foreman_spec'])

        if 'id' in updated_interface:
            expected_interfaces_ids.add(updated_interface['id'])

    for leftover_interface in current_interfaces_ids - expected_interfaces_ids:
        module.ensure_entity('interfaces', {}, {'id': leftover_interface}, params=scope, state='absent',
                             foreman_spec=module.foreman_spec['interfaces_attributes']['foreman_spec'])


class ForemanHostModule(HostMixin, ForemanEntityAnsibleModule):
    pass


def main():
    module = ForemanHostModule(
        foreman_spec=dict(
            name=dict(required=True),
            hostgroup=dict(type='entity'),
            location=dict(type='entity'),
            organization=dict(type='entity'),
            enabled=dict(type='bool'),
            managed=dict(type='bool'),
            build=dict(type='bool'),
            ip=dict(),
            mac=dict(),
            comment=dict(),
            owner=dict(type='entity', resource_type='users', flat_name='owner_id'),
            owner_group=dict(type='entity', resource_type='usergroups', flat_name='owner_id'),
            owner_type=dict(invisible=True),
            provision_method=dict(choices=['build', 'image', 'bootdisk']),
            image=dict(type='entity', scope=['compute_resource']),
            compute_attributes=dict(type='dict'),
            interfaces_attributes=dict(type='nested_list', foreman_spec=interfaces_spec, ensure=True),
        ),
        mutually_exclusive=[
            ['owner', 'owner_group']
        ],
        required_by=dict(
            image=('compute_resource',),
        ),
    )

    # additional param validation
    if '.' not in module.foreman_params['name']:
        module.fail_json(msg="The hostname must be FQDN")

    if not module.desired_absent:
        if 'build' in module.foreman_params and module.foreman_params['build']:
            # When 'build'=True, 'managed' has to be True. Assuming that user's priority is to build.
            if 'managed' in module.foreman_params and not module.foreman_params['managed']:
                module.warn("when 'build'=True, 'managed' is ignored and forced to True")
            module.foreman_params['managed'] = True
        elif 'build' not in module.foreman_params and 'managed' in module.foreman_params and not module.foreman_params['managed']:
            # When 'build' is not given and 'managed'=False, have to clear 'build' context that might exist on the server.
            module.foreman_params['build'] = False

        if 'mac' in module.foreman_params:
            module.foreman_params['mac'] = module.foreman_params['mac'].lower()

        if 'owner' in module.foreman_params:
            module.foreman_params['owner_type'] = 'User'
        elif 'owner_group' in module.foreman_params:
            module.foreman_params['owner_type'] = 'Usergroup'

    with module.api_connection():
        entity = module.lookup_entity('entity', params={'show_hidden_parameters': True})

        if not module.desired_absent:
            module.auto_lookup_entities()

        if 'image' in module.foreman_params:
            if 'compute_attributes' not in module.foreman_params:
                module.foreman_params['compute_attributes'] = {}
            module.foreman_params['compute_attributes']['image_id'] = module.foreman_params['image']['uuid']

        if 'compute_resource' in module.foreman_params:
            compute_resource = module.foreman_params['compute_resource']
            cluster = None
            if 'compute_attributes' in module.foreman_params:
                if 'cluster' in module.foreman_params['compute_attributes']:
                    cluster = module.find_cluster(module.foreman_params['compute_attributes']['cluster'], compute_resource)
                    module.foreman_params['compute_attributes']['cluster'] = cluster['_api_identifier']

                if 'volumes_attributes' in module.foreman_params['compute_attributes']:
                    for volume in module.foreman_params['compute_attributes']['volumes_attributes'].values():
                        if 'storage_pod' in volume:
                            storage_pod = module.find_storage_pod(volume['storage_pod'], compute_resource, cluster)
                            volume['storage_pod'] = storage_pod['name']
                        if 'storage_domain' in volume:
                            storage_domain = module.find_storage_domain(volume['storage_domain'], compute_resource, cluster)
                            volume['storage_domain'] = storage_domain['id']

            if 'interfaces_attributes' in module.foreman_params:
                for interface in module.foreman_params['interfaces_attributes']:
                    if 'compute_attributes' in interface and 'network' in interface['compute_attributes']:
                        network = module.find_network(interface['compute_attributes']['network'], compute_resource, cluster)
                        interface['compute_attributes']['network'] = network['id']

        # We use different APIs for creating a host with interfaces
        # and updating it, so let's differentiate based on entity being present or not
        if entity and 'interfaces_attributes' in module.foreman_params:
            interfaces = module.foreman_params.pop('interfaces_attributes')
        else:
            interfaces = None

        expected_puppetclasses = module.foreman_params.pop('puppetclasses', None)

        entity = module.run()

        if not module.desired_absent:
            if 'environment_id' in entity:
                ensure_puppetclasses(module, 'host', entity, expected_puppetclasses)
            if interfaces is not None:
                ensure_host_interfaces(module, entity, interfaces)


if __name__ == '__main__':
    main()
