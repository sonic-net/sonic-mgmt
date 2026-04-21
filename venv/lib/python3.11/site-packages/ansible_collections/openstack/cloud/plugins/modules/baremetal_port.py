#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021 by Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
module: baremetal_port
short_description: Create/Delete Bare Metal port Resources from OpenStack
author: OpenStack Ansible SIG
description:
    - Create, Update and Remove ironic ports from OpenStack.
options:
    address:
      description:
        - Physical hardware address of this network Port, typically the
          hardware MAC address.
      type: str
    extra:
      description:
        - A set of one or more arbitrary metadata key and value pairs.
      type: dict
    id:
      description:
        - ID of the Port.
        - Will be auto-generated if not specified.
      type: str
      aliases: ['uuid']
    is_pxe_enabled:
      description:
        - Whether PXE should be enabled or disabled on the Port.
      type: bool
      aliases: ['pxe_enabled']
    local_link_connection:
      description:
        - The Port binding profile.
      type: dict
      suboptions:
        switch_id:
          description:
            - A MAC address or an OpenFlow based datapath_id of the switch.
          type: str
        port_id:
          description:
            - Identifier of the physical port on the switch to which node's
              port is connected to.
          type: str
        switch_info:
          description:
            - An optional string field to be used to store any vendor-specific
              information.
          type: str
    node:
      description:
        - ID or Name of the Node this resource belongs to.
      type: str
    physical_network:
      description:
        - The name of the physical network to which a port is connected.
      type: str
    port_group:
      description:
        - ID or Name of the portgroup this resource belongs to.
      type: str
      aliases: ['portgroup']
    state:
      description:
        - Indicates desired state of the resource
      choices: ['present', 'absent']
      default: present
      type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Create Bare Metal port
  openstack.cloud.baremetal_port:
    cloud: devstack
    state: present
    node: bm-0
    address: fa:16:3e:aa:aa:aa
    is_pxe_enabled: True
    local_link_connection:
      switch_id: 0a:1b:2c:3d:4e:5f
      port_id: Ethernet3/1
      switch_info: switch1
    extra:
      something: extra
    physical_network: datacenter
  register: result

- name: Delete Bare Metal port
  openstack.cloud.baremetal_port:
    cloud: devstack
    state: absent
    address: fa:16:3e:aa:aa:aa
  register: result

- name: Update Bare Metal port
  openstack.cloud.baremetal_port:
    cloud: devstack
    state: present
    id: 1a85ebca-22bf-42eb-ad9e-f640789b8098
    is_pxe_enabled: False
    local_link_connection:
      switch_id: a0:b1:c2:d3:e4:f5
      port_id: Ethernet4/12
      switch_info: switch2
'''

RETURN = r'''
port:
    description: A port dictionary, subset of the dictionary keys listed below
                 may be returned, depending on your cloud provider.
    returned: success
    type: dict
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
            description: A set of one or more arbitrary metadata key and value
                         pairs.
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
            description: The Port binding profile. If specified, must contain
                         switch_id (only a MAC address or an OpenFlow based
                         datapath_id of the switch are accepted in this field
                         and port_id (identifier of the physical port on the
                         switch to which node's port is connected to) fields.
                         switch_info is an optional string field to be used to
                         store any vendor-specific information.
            returned: success
            type: dict
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


class BaremetalPortModule(OpenStackModule):
    argument_spec = dict(
        address=dict(),
        extra=dict(type='dict'),
        id=dict(aliases=['uuid']),
        is_pxe_enabled=dict(type='bool', aliases=['pxe_enabled']),
        local_link_connection=dict(type='dict'),
        node=dict(),
        physical_network=dict(),
        port_group=dict(aliases=['portgroup']),
        state=dict(default='present', choices=['present', 'absent']),
    )

    module_kwargs = dict(
        required_one_of=[
            ('id', 'address'),
        ],
        required_if=[
            ('state', 'present', ('node', 'address',), False),
        ],
    )

    def run(self):
        port = self._find_port()
        state = self.params['state']
        if state == 'present':
            # create or update port

            kwargs = {}
            id = self.params['id']
            if id:
                kwargs['id'] = id

            node_name_or_id = self.params['node']
            # assert node_name_or_id
            node = self.conn.baremetal.find_node(node_name_or_id,
                                                 ignore_missing=False)
            kwargs['node_id'] = node['id']

            port_group_name_or_id = self.params['port_group']
            if port_group_name_or_id:
                port_group = self.conn.baremetal.find_port_group(
                    port_group_name_or_id, ignore_missing=False)
                kwargs['port_group_id'] = port_group['id']

            for k in ['address', 'extra', 'is_pxe_enabled',
                      'local_link_connection', 'physical_network']:
                if self.params[k] is not None:
                    kwargs[k] = self.params[k]

            changed = True
            if not port:
                # create port
                port = self.conn.baremetal.create_port(**kwargs)
            else:
                # update port
                updates = dict((k, v)
                               for k, v in kwargs.items()
                               if v != port[k])

                if updates:
                    port = \
                        self.conn.baremetal.update_port(port['id'], **updates)
                else:
                    changed = False

            self.exit_json(changed=changed, port=port.to_dict(computed=False))

        if state == 'absent':
            # remove port
            if not port:
                self.exit_json(changed=False)

            port = self.conn.baremetal.delete_port(port['id'])
            self.exit_json(changed=True)

    def _find_port(self):
        id = self.params['id']
        if id:
            return self.conn.baremetal.get_port(id)

        address = self.params['address']
        if address:
            ports = list(self.conn.baremetal.ports(address=address,
                                                   details=True))

            if len(ports) == 1:
                return ports[0]
            elif len(ports) > 1:
                raise ValueError(
                    'Multiple ports with address {address} found. A ID'
                    ' must be defined in order to identify a unique'
                    ' port.'.format(address=address))
            else:
                return None

        raise AssertionError("id or address must be specified")


def main():
    module = BaremetalPortModule()
    module()


if __name__ == "__main__":
    main()
