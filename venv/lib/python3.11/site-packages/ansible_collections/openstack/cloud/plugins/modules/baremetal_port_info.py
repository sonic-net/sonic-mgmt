#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021 by Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
module: baremetal_port_info
short_description: Retrieve information about Bare Metal ports from OpenStack
author: OpenStack Ansible SIG
description:
    - Retrieve information about Bare Metal ports from OpenStack.
options:
    address:
      description:
        - Physical hardware address of this network Port, typically the
          hardware MAC address.
      type: str
    name:
      description:
        - Name or ID of the Bare Metal port.
      type: str
      aliases: ['uuid']
    node:
      description:
        - Name or ID of a Bare Metal node.
      type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Gather information about all baremetal ports
  openstack.cloud.baremetal_port_info:
    cloud: devstack

- name: Gather information about a baremetal port by address
  openstack.cloud.baremetal_port_info:
    cloud: devstack
    address: fa:16:3e:aa:aa:aa

- name: Gather information about a baremetal port by address
  openstack.cloud.baremetal_port_info:
    cloud: devstack
    name: a2b6bd99-77b9-43f0-9ddc-826568e68dec

- name: Gather information about a baremetal ports associated with a node
  openstack.cloud.baremetal_port_info:
    cloud: devstack
    node: bm-0
'''

RETURN = r'''
ports:
    description: Bare Metal port list.
    returned: always
    type: list
    elements: dict
    contains:
        address:
            description: Physical hardware address of this network Port,
                         typically the hardware MAC address.
            returned: success
            type: str
        created_at:
            description: Bare Metal port created at timestamp.
            returned: success
            type: str
        extra:
            description: A set of one or more arbitrary metadata key and
                         value pairs.
            returned: success
            type: dict
        id:
            description: The UUID for the Baremetal Port resource.
            returned: success
            type: str
        internal_info:
            description: Internal metadata set and stored by the Port. This
                         field is read-only.
            returned: success
            type: dict
        is_pxe_enabled:
            description: Whether PXE is enabled or disabled on the Port.
            returned: success
            type: bool
        links:
            description: A list of relative links, including the self and
                         bookmark links.
            returned: success
            type: list
        local_link_connection:
            description: The Port binding profile.
            returned: success
            type: dict
            contains:
              switch_id:
                description: A MAC address or an OpenFlow based datapath_id of
                             the switch.
                type: str
              port_id:
                description: Identifier of the physical port on the switch to
                             which node's port is connected to.
                type: str
              switch_info:
                description: An optional string field to be used to store any
                             vendor-specific information.
                type: str
        location:
            description: Cloud location of this resource (cloud, project,
                         region, zone)
            returned: success
            type: dict
        name:
            description: Bare Metal port name.
            returned: success
            type: str
        node_id:
            description: UUID of the Bare Metal Node this resource belongs to.
            returned: success
            type: str
        physical_network:
            description: The name of the physical network to which a port is
                         connected.
            returned: success
            type: str
        port_group_id:
            description: UUID  of the Portgroup this resource belongs to.
            returned: success
            type: str
        updated_at:
            description: Bare Metal port updated at timestamp.
            returned: success
            type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule
)


class BaremetalPortInfoModule(OpenStackModule):
    argument_spec = dict(
        address=dict(),
        name=dict(aliases=['uuid']),
        node=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True,
    )

    def _fetch_ports(self):
        name_or_id = self.params['name']

        if name_or_id:
            port = self.conn.baremetal.find_port(name_or_id)
            return [port] if port else []

        kwargs = {}
        address = self.params['address']
        if address:
            kwargs['address'] = address

        node_name_or_id = self.params['node']
        if node_name_or_id:
            node = self.conn.baremetal.find_node(node_name_or_id)
            if node:
                kwargs['node_uuid'] = node['id']
            else:
                # node does not exist so no port could possibly be found
                return []

        return self.conn.baremetal.ports(details=True, **kwargs)

    def run(self):
        ports = [port.to_dict(computed=False)
                 for port in self._fetch_ports()]

        self.exit_json(changed=False,
                       ports=ports,
                       # keep for backward compatibility
                       baremetal_ports=ports)


def main():
    module = BaremetalPortInfoModule()
    module()


if __name__ == "__main__":
    main()
