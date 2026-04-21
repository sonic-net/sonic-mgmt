#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 IBM
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
module: port_info
short_description: Retrieve information about ports within OpenStack.
author: OpenStack Ansible SIG
description:
    - Retrieve information about ports from OpenStack.
options:
    name:
        description:
            - Unique name or ID of a port.
        type: str
        aliases: ['port']
    filters:
        description:
            - A dictionary of meta data to use for further filtering. Elements
              of this dictionary will be matched passed to the API as query
              parameter filters.
        type: dict
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
# Gather information about all ports
- openstack.cloud.port_info:
    cloud: mycloud
  register: result

- debug:
    msg: "{{ result.ports}}"

# Gather information about a single port
- openstack.cloud.port_info:
    cloud: mycloud
    name: 6140317d-e676-31e1-8a4a-b1913814a471

# Gather information about all ports that have device_id set to a specific
# value and with a status of ACTIVE.
- openstack.cloud.port_info:
    cloud: mycloud
    filters:
      device_id: 1038a010-3a37-4a9d-82ea-652f1da36597
      status: ACTIVE
'''

RETURN = '''
ports:
    description: |
        List of port dictionaries. A subset of the dictionary keys listed below
        may be returned, depending on your cloud provider.
    returned: always
    type: list
    elements: dict
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


class PortInfoModule(OpenStackModule):
    argument_spec = dict(
        name=dict(aliases=['port']),
        filters=dict(type='dict'),
    )
    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        ports = [p.to_dict(computed=False) for p in
                 self.conn.search_ports(
                     name_or_id=self.params['name'],
                     filters=self.params['filters'])]

        self.exit_json(changed=False, ports=ports)


def main():
    module = PortInfoModule()
    module()


if __name__ == '__main__':
    main()
