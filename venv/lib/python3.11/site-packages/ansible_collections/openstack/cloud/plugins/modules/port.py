#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: port
short_description: Add/Update/Delete ports from an OpenStack cloud.
author: OpenStack Ansible SIG
description:
   - Add, Update or Remove ports from an OpenStack cloud.
options:
    allowed_address_pairs:
        description:
          - "Allowed address pairs list. Allowed address pairs are supported
            with dictionary structure.
            e.g.  allowed_address_pairs:
                    - ip_address: 10.1.0.12
                      mac_address: ab:cd:ef:12:34:56
                    - ip_address: ..."
          - The port will change during update if not all suboptions are
            specified, e.g. when ip_address is given but mac_address is not.
        type: list
        elements: dict
        suboptions:
            ip_address:
                description: The IP address.
                type: str
            mac_address:
                description: The MAC address.
                type: str
    binding_profile:
        description:
          - Binding profile dict that the port should be created with.
        type: dict
    binding_vnic_type:
        description:
          - The type of the port that should be created
        choices: [normal,
                  direct,
                  direct-physical,
                  macvtap,
                  baremetal,
                  virtio-forwarder]
        type: str
        aliases: ['vnic_type']
    description:
        description:
          - Description of the port.
        type: str
    device_id:
        description:
          - Device ID of device using this port.
        type: str
    device_owner:
        description:
           - The ID of the entity that uses this port.
        type: str
    dns_domain:
        description:
          - The dns domain of the port ( only with dns-integration enabled )
        type: str
    dns_name:
        description:
          - The dns name of the port ( only with dns-integration enabled )
        type: str
    extra_dhcp_opts:
        description:
          - "Extra dhcp options to be assigned to this port. Extra options are
            supported with dictionary structure. Note that options cannot be
            removed only updated.
            e.g.  extra_dhcp_opts:
                    - ip_version: 4
                      opt_name: bootfile-name
                      opt_value: pxelinux.0
                    - opt_name: ..."
          - The port will change during update if not all suboptions are
            specified, e.g. when opt_name is given but ip_version is not.
        type: list
        elements: dict
        suboptions:
            ip_version:
                description: The IP version this DHCP option is for.
                type: int
                required: true
            opt_name:
                description: The name of the DHCP option to set.
                type: str
                required: true
            opt_value:
                description: The value of the DHCP option to set.
                type: str
                required: true
    fixed_ips:
        description:
          - Desired IP and/or subnet for this port.  Subnet is referenced by
            subnet_id and IP is referenced by ip_address.
          - The port will change during update if not all suboptions are
            specified, e.g. when ip_address is given but subnet_id is not.
        type: list
        elements: dict
        suboptions:
            ip_address:
                description: The fixed IP address to attempt to allocate.
                required: true
                type: str
            subnet_id:
                description: The subnet to attach the IP address to.
                type: str
    is_admin_state_up:
        description:
          - Sets admin state.
        type: bool
        aliases: ['admin_state_up']
    mac_address:
        description:
          - MAC address of this port.
        type: str
    name:
        description:
          - Name that has to be given to the port.
          - This port attribute cannot be updated.
        type: str
        required: true
    network:
        description:
          - ID or name of the network this port belongs to.
          - Required when creating a new port.
          - Must be a name when creating a port.
          - This port attribute cannot be updated.
        type: str
    no_security_groups:
        description:
          - Do not associate a security group with this port.
          - "Deprecated. Use I(security_groups): C([]) instead
            of I(no_security_groups): C(true)."
        type: bool
        default: 'false'
    is_port_security_enabled:
        description:
          - Whether to enable or disable the port security on the network.
        type: bool
        aliases: ['port_security_enabled']
    security_groups:
        description:
          - Security group(s) ID(s) or name(s) associated with the port.
        type: list
        elements: str
    state:
        description:
          - Should the resource be present or absent.
        choices: [present, absent]
        default: present
        type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
# Create a port
- openstack.cloud.port:
    state: present
    auth:
      auth_url: https://identity.example.com
      username: admin
      password: admin
      project_name: admin
    name: port1
    network: foo

# Create a port with a static IP
- openstack.cloud.port:
    state: present
    auth:
      auth_url: https://identity.example.com
      username: admin
      password: admin
      project_name: admin
    name: port1
    network: foo
    fixed_ips:
      - ip_address: 10.1.0.21

# Create a port with No security groups
- openstack.cloud.port:
    state: present
    auth:
      auth_url: https://identity.example.com
      username: admin
      password: admin
      project_name: admin
    name: port1
    network: foo
    no_security_groups: True

# Update the existing 'port1' port with multiple security groups (version 1)
- openstack.cloud.port:
    state: present
    auth:
      auth_url: https://identity.example.com
      username: admin
      password: admin
      project_name: admin
    name: port1
    security_groups: 1496e8c7-4918-482a-9172-f4f00fc4a3a5,057d4bdf-6d4d-472...

# Update the existing 'port1' port with multiple security groups (version 2)
- openstack.cloud.port:
    state: present
    auth:
      auth_url: https://identity.example.com
      username: admin
      password: admin
      project_name: admin
    name: port1
    security_groups:
      - 1496e8c7-4918-482a-9172-f4f00fc4a3a5
      - 057d4bdf-6d4d-472...

# Create port of type 'direct'
- openstack.cloud.port:
    state: present
    auth:
      auth_url: https://identity.example.com
      username: admin
      password: admin
      project_name: admin
    name: port1
    network: foo
    binding_vnic_type: direct

# Create a port with binding profile
- openstack.cloud.port:
    state: present
    auth:
      auth_url: https://identity.example.com
      username: admin
      password: admin
      project_name: admin
    name: port1
    network: foo
    binding_profile:
      pci_slot: "0000:03:11.1"
      physical_network: "provider"
'''

RETURN = '''
port:
    description: Dictionary describing the port.
    type: dict
    returned: On success when I(state) is C(present).
    contains:
        allowed_address_pairs:
            description: Allowed address pairs.
            returned: success
            type: list
            sample: []
        binding_host_id:
            description: |
                The ID of the host where the port is allocated. In some cases,
                different implementations can run on different hosts.
            returned: success
            type: str
            sample: "b4bd682d-234a-4091-aa5b-4b025a6a7759"
        binding_profile:
            description: |
                A dictionary the enables the application running on the
                specified host to pass and receive vif port-specific
                information to the plug-in.
            returned: success
            type: dict
            sample: {}
        binding_vif_details:
            description: |
                A dictionary that enables the application to pass
                information about functions that the Networking API provides.
            returned: success
            type: dict
        binding_vif_type:
            description: The VIF type for the port.
            returned: success
            type: dict
        binding_vnic_type:
            description: |
                The virtual network interface card (vNIC) type that is
                bound to the neutron port.
            returned: success
            type: str
            sample: "normal"
        created_at:
            description: Timestamp when the port was created.
            returned: success
            type: str
            sample: "2022-02-03T13:28:25Z"
        data_plane_status:
            description: Status of the underlying data plane of a port.
            returned: success
            type: str
        description:
            description: The port description.
            returned: success
            type: str
        device_id:
            description: Device ID of this port.
            returned: success
            type: str
            sample: "b4bd682d-234a-4091-aa5b-4b025a6a7759"
        device_owner:
            description: Device owner of this port, e.g. C(network:dhcp).
            returned: success
            type: str
            sample: "network:router_interface"
        device_profile:
            description: |
                Device profile of this port, refers to Cyborg device-profiles:
                https://docs.openstack.org/api-ref/accelerator/v2/index.html#
                device-profiles.
            returned: success
            type: str
        dns_assignment:
            description: DNS assignment for the port.
            returned: success
            type: list
        dns_domain:
            description: DNS domain assigned to the port.
            returned: success
            type: str
        dns_name:
            description: DNS name for the port.
            returned: success
            type: str
        extra_dhcp_opts:
            description: |
                A set of zero or more extra DHCP option pairs.
                An option pair consists of an option value and name.
            returned: success
            type: list
            sample: []
        fixed_ips:
            description: |
                IP addresses for the port. Includes the IP address and subnet
                ID.
            returned: success
            type: list
        id:
            description: The port ID.
            returned: success
            type: str
            sample: "3ec25c97-7052-4ab8-a8ba-92faf84148de"
        ip_allocation:
            description: |
                The ip_allocation indicates when ports use deferred,
                immediate or no IP allocation.
            returned: success
            type: str
        is_admin_state_up:
            description: |
                The administrative state of the port, which is up C(True) or
                down C(False).
            returned: success
            type: bool
            sample: true
        is_port_security_enabled:
            description: |
                The port security status, which is enabled C(True) or disabled
                C(False).
            returned: success
            type: bool
            sample: false
        mac_address:
            description: The MAC address of an allowed address pair.
            returned: success
            type: str
            sample: "00:00:5E:00:53:42"
        name:
            description: The port name.
            returned: success
            type: str
            sample: "port_name"
        network_id:
            description: The ID of the attached network.
            returned: success
            type: str
            sample: "dd1ede4f-3952-4131-aab6-3b8902268c7d"
        numa_affinity_policy:
            description: |
                The NUMA affinity policy defined for this port.
            returned: success
            type: str
            sample: "required"
        project_id:
            description: The ID of the project who owns the network.
            returned: success
            type: str
            sample: "aa1ede4f-3952-4131-aab6-3b8902268c7d"
        propagate_uplink_status:
            description: Whether to propagate uplink status of the port.
            returned: success
            type: bool
            sample: false
        qos_network_policy_id:
            description: |
                The ID of the QoS policy attached to the network where the
                port is bound.
            returned: success
            type: str
            sample: "1e4f3958-c0c9-4dec-82fa-ed2dc1c5cb34"
        qos_policy_id:
            description: The ID of the QoS policy attached to the port.
            returned: success
            type: str
            sample: "b20bb47f-5d6d-45a6-8fe7-2c1b44f0db73"
        resource_request:
            description: |
                The port-resource-request exposes Placement resources
                (i.e.: minimum-bandwidth) and traits (i.e.: vnic-type, physnet)
                requested by a port to Nova and Placement.
            returned: success
            type: str
        revision_number:
            description: The revision number of the resource.
            returned: success
            type: int
            sample: 0
        security_group_ids:
            description: The IDs of any attached security groups.
            returned: success
            type: list
        status:
            description: The port status. Value is C(ACTIVE) or C(DOWN).
            returned: success
            type: str
            sample: "ACTIVE"
        tags:
            description: The list of tags on the resource.
            returned: success
            type: list
            sample: []
        tenant_id:
            description: Same as I(project_id). Deprecated.
            returned: success
            type: str
            sample: "51fce036d7984ba6af4f6c849f65ef00"
        trunk_details:
            description: |
                The trunk referring to this parent port and its subports.
                Present for trunk parent ports if C(trunk-details) extension
                is loaded.
            returned: success
            type: dict
        updated_at:
            description: Timestamp when the port was last updated.
            returned: success
            type: str
            sample: "2022-02-03T13:28:25Z"
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class PortModule(OpenStackModule):
    argument_spec = dict(
        allowed_address_pairs=dict(type='list', elements='dict'),
        binding_profile=dict(type='dict'),
        binding_vnic_type=dict(choices=['normal', 'direct', 'direct-physical',
                                        'macvtap', 'baremetal',
                                        'virtio-forwarder'],
                               aliases=['vnic_type']),
        description=dict(),
        device_id=dict(),
        device_owner=dict(),
        dns_domain=dict(),
        dns_name=dict(),
        extra_dhcp_opts=dict(type='list', elements='dict'),
        fixed_ips=dict(type='list', elements='dict'),
        is_admin_state_up=dict(type='bool', aliases=['admin_state_up']),
        mac_address=dict(),
        name=dict(required=True),
        network=dict(),
        no_security_groups=dict(default=False, type='bool'),
        is_port_security_enabled=dict(type='bool', aliases=['port_security_enabled']),
        security_groups=dict(type='list', elements='str'),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = dict(
        mutually_exclusive=[
            ['no_security_groups', 'security_groups'],
        ],
        required_if=[
            ('state', 'present', ('network',)),
        ],
        supports_check_mode=True
    )

    def run(self):
        network_name_or_id = self.params['network']
        port_name_or_id = self.params['name']
        state = self.params['state']

        network = None
        if network_name_or_id:
            network = self.conn.network.find_network(
                network_name_or_id, ignore_missing=False)

        port = self.conn.network.find_port(
            port_name_or_id,
            # use network id in query if network parameter was specified
            **(dict(network_id=network.id) if network else dict()))

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(port, state))

        if state == 'present' and not port:
            # create port
            port = self._create(network)
            self.exit_json(changed=True,
                           port=port.to_dict(computed=False))
        elif state == 'present' and port:
            # update port
            update = self._build_update(port)
            if update:
                port = self._update(port, update)

            self.exit_json(changed=bool(update),
                           port=port.to_dict(computed=False))
        elif state == 'absent' and port:
            # delete port
            self._delete(port)
            self.exit_json(changed=True)
        elif state == 'absent' and not port:
            # do nothing
            self.exit_json(changed=False)

    def _build_update(self, port):
        update = {}

        # A port's name cannot be updated by this module because
        # it is used to find ports by name or id.
        # If name is an id, then we do not have a name to update.
        # If name is a name actually, then it was used to find a
        # matching port hence the name is the user defined one
        # already.

        # updateable port attributes in openstacksdk
        # (OpenStack API names in braces):
        # - allowed_address_pairs (allowed_address_pairs)
        # - binding_host_id (binding:host_id)
        # - binding_profile (binding:profile)
        # - binding_vnic_type (binding:vnic_type)
        # - data_plane_status (data_plane_status)
        # - description (description)
        # - device_id (device_id)
        # - device_owner (device_owner)
        # (- device_profile (device_profile))
        # - dns_domain (dns_domain)
        # - dns_name (dns_name)
        # - extra_dhcp_opts (extra_dhcp_opts)
        # - fixed_ips (fixed_ips)
        # - is_admin_state_up (admin_state_up)
        # - is_port_security_enabled (port_security_enabled)
        # - mac_address (mac_address)
        # - name (name)
        # - numa_affinity_policy (numa_affinity_policy)
        # - qos_policy_id (qos_policy_id)
        # - security_group_ids (security_groups)
        # Ref.: https://docs.openstack.org/api-ref/network/v2/index.html#update-port

        # Update all known updateable attributes although
        # our module might not support them yet

        # Update attributes which can be compared straight away
        port_attributes = dict(
            (k, self.params[k])
            for k in ['binding_host_id', 'binding_vnic_type',
                      'data_plane_status', 'description', 'device_id',
                      'device_owner', 'is_admin_state_up',
                      'is_port_security_enabled', 'mac_address',
                      'numa_affinity_policy']
            if k in self.params and self.params[k] is not None
            and self.params[k] != port[k])

        # Compare dictionaries
        for k in ['binding_profile']:
            if self.params[k] is None:
                continue

            if (self.params[k] or port[k]) \
               and self.params[k] != port[k]:
                port_attributes[k] = self.params[k]

        # Attribute qos_policy_id is not supported by this module and would
        # need special handling using self.conn.network.find_qos_policy()

        # Compare attributes which are lists of dictionaries
        for k in ['allowed_address_pairs', 'extra_dhcp_opts', 'fixed_ips']:
            if self.params[k] is None:
                continue

            if (self.params[k] or port[k]) \
               and self.params[k] != port[k]:
                port_attributes[k] = self.params[k]

        # Compare security groups
        if self.params['no_security_groups']:
            security_group_ids = []
        elif self.params['security_groups'] is not None:
            security_group_ids = [
                self.conn.network.find_security_group(
                    security_group_name_or_id, ignore_missing=False).id
                for security_group_name_or_id in self.params['security_groups']
            ]
        else:
            security_group_ids = None

        if security_group_ids is not None \
           and set(security_group_ids) != set(port['security_group_ids']):
            port_attributes['security_group_ids'] = security_group_ids

        # Compare dns attributes
        if self.conn.has_service('dns') and \
           self.conn.network.find_extension('dns-integration'):
            port_attributes.update(dict(
                (k, self.params[k])
                for k in ['dns_name', 'dns_domain']
                if self.params[k] is not None and self.params[k] != port[k]
            ))

        if port_attributes:
            update['port_attributes'] = port_attributes
        return update

    def _create(self, network):
        args = {}
        args['network_id'] = network.id

        # Fetch IDs of security groups next to fail early
        # if any security group does not exist
        if self.params['no_security_groups']:
            args['security_group_ids'] = []
        elif self.params['security_groups'] is not None:
            args['security_group_ids'] = [
                self.conn.network.find_security_group(
                    security_group_name_or_id, ignore_missing=False).id
                for security_group_name_or_id in self.params['security_groups']
            ]

        for k in ['allowed_address_pairs',
                  'binding_profile',
                  'binding_vnic_type',
                  'device_id',
                  'device_owner',
                  'description',
                  'extra_dhcp_opts',
                  'is_admin_state_up',
                  'mac_address',
                  'is_port_security_enabled',
                  'fixed_ips',
                  'name']:
            if self.params[k] is not None:
                args[k] = self.params[k]

        if self.conn.has_service('dns') \
           and self.conn.network.find_extension('dns-integration'):
            for k in ['dns_domain', 'dns_name']:
                if self.params[k] is not None:
                    args[k] = self.params[k]

        return self.conn.network.create_port(**args)

    def _delete(self, port):
        self.conn.network.delete_port(port.id)

    def _update(self, port, update):
        port_attributes = update.get('port_attributes')
        if port_attributes:
            port = self.conn.network.update_port(port, **port_attributes)
        return port

    def _will_change(self, port, state):
        if state == 'present' and not port:
            return True
        elif state == 'present' and port:
            return bool(self._build_update(port))
        elif state == 'absent' and port:
            return True
        else:
            # state == 'absent' and not port:
            return False


def main():
    module = PortModule()
    module()


if __name__ == '__main__':
    main()
