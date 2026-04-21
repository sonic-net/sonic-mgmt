#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2013, Benno Joy <benno@ansible.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: network
short_description: Creates/removes networks from OpenStack
author: OpenStack Ansible SIG
description:
   - Add, update or remove network from OpenStack.
options:
   name:
     description:
        - Name to be assigned to the network.
     required: true
     type: str
   shared:
     description:
        - Whether this network is shared or not.
     type: bool
   admin_state_up:
     description:
        - Whether the state should be marked as up or down.
     type: bool
   external:
     description:
        - Whether this network is externally accessible.
     type: bool
   is_default:
     description:
        - Whether this network is default network or not. This is only effective
          with external networks.
     type: bool
   is_vlan_transparent:
     description:
        - Whether this network is vlan_transparent or not.
     type: bool
   state:
     description:
        - Indicate desired state of the resource.
     choices: ['present', 'absent']
     default: present
     type: str
   provider_physical_network:
     description:
        - The physical network where this network object is implemented.
     type: str
   provider_network_type:
     description:
        - The type of physical network that maps to this network resource.
     type: str
   provider_segmentation_id:
     description:
        - An isolated segment on the physical network. The I(network_type)
          attribute defines the segmentation model. For example, if the
          I(network_type) value is vlan, this ID is a vlan identifier. If
          the I(network_type) value is gre, this ID is a gre key.
     type: int
   project:
     description:
        - Project name or ID containing the network (name admin-only)
     type: str
   port_security_enabled:
     description:
        -  Whether port security is enabled on the network or not.
           Network will use OpenStack defaults if this option is
           not utilised.
     type: bool
   mtu:
     description:
       -  The maximum transmission unit (MTU) value to address fragmentation.
          Network will use OpenStack defaults if this option is
          not provided.
     type: int
     aliases: ['mtu_size']
   dns_domain:
     description:
       -  The DNS domain value to set.
          Network will use Openstack defaults if this option is
          not provided.
     type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
# Create an externally accessible network named 'ext_network'.
- openstack.cloud.network:
    cloud: mycloud
    state: present
    name: ext_network
    external: true
'''

RETURN = '''
id:
    description: Id of network
    returned: On success when network exists.
    type: str
network:
    description: Dictionary describing the network.
    returned: On success when network exists.
    type: dict
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


class NetworkModule(OpenStackModule):

    argument_spec = dict(
        name=dict(required=True),
        shared=dict(type='bool'),
        admin_state_up=dict(type='bool'),
        external=dict(type='bool'),
        is_default=dict(type='bool'),
        is_vlan_transparent=dict(type='bool'),
        provider_physical_network=dict(),
        provider_network_type=dict(),
        provider_segmentation_id=dict(type='int'),
        state=dict(default='present', choices=['absent', 'present']),
        project=dict(),
        port_security_enabled=dict(type='bool'),
        mtu=dict(type='int', aliases=['mtu_size']),
        dns_domain=dict()
    )

    def run(self):

        state = self.params['state']
        name = self.params['name']
        shared = self.params['shared']
        admin_state_up = self.params['admin_state_up']
        external = self.params['external']
        is_default = self.params['is_default']
        is_vlan_transparent = self.params['is_vlan_transparent']
        provider_physical_network = self.params['provider_physical_network']
        provider_network_type = self.params['provider_network_type']
        provider_segmentation_id = self.params['provider_segmentation_id']
        project = self.params['project']

        kwargs = {}
        for arg in ('port_security_enabled', 'mtu', 'dns_domain'):
            if self.params[arg] is not None:
                kwargs[arg] = self.params[arg]

        if project is not None:
            proj = self.conn.identity.find_project(project,
                                                   ignore_missing=False)
            project_id = proj['id']
            net_kwargs = {'project_id': project_id}
        else:
            project_id = None
            net_kwargs = {}
        net = self.conn.network.find_network(name, **net_kwargs)

        if state == 'present':
            if provider_physical_network:
                kwargs['provider_physical_network'] = provider_physical_network
            if provider_network_type:
                kwargs['provider_network_type'] = provider_network_type
            if provider_segmentation_id:
                kwargs['provider_segmentation_id'] = provider_segmentation_id

            if project_id is not None:
                kwargs['project_id'] = project_id

            if shared is not None:
                kwargs["shared"] = shared
            if admin_state_up is not None:
                kwargs["admin_state_up"] = admin_state_up
            if external is not None:
                kwargs["is_router_external"] = external
            if is_default is not None:
                kwargs["is_default"] = is_default
            if is_vlan_transparent is not None:
                kwargs["is_vlan_transparent"] = is_vlan_transparent

            if not net:
                net = self.conn.network.create_network(name=name, **kwargs)
                changed = True
            else:
                changed = False
                update_kwargs = {}

                # Check we are not trying to update an properties that cannot
                # be modified
                non_updatables = [
                    "provider_network_type",
                    "provider_physical_network",
                ]
                for arg in non_updatables:
                    if arg in kwargs and kwargs[arg] != net[arg]:
                        self.fail_json(
                            msg="The following parameters cannot be updated: "
                                "%s. You will need to use state: absent and "
                                "recreate." % ', '.join(non_updatables)
                        )

                # Filter args to update call to the ones that have been modifed
                # and are updatable. Adapted from:
                # https://github.com/openstack/openstacksdk/blob/1ce15c9a8758b4d978eb5239bae100ddc13c8875/openstack/cloud/_network.py#L559-L561
                for arg in ["shared", "admin_state_up", "is_router_external",
                            "mtu", "port_security_enabled", "dns_domain",
                            "provider_segmentation_id"]:
                    if (
                        arg in kwargs
                        # ensure user wants something specific
                        and kwargs[arg] is not None
                        # and this is not what we have right now
                        and kwargs[arg] != net[arg]
                    ):
                        update_kwargs[arg] = kwargs[arg]

                if update_kwargs:
                    net = self.conn.network.update_network(
                        net.id, **update_kwargs
                    )
                    changed = True

            net = net.to_dict(computed=False)
            self.exit(changed=changed, network=net, id=net['id'])
        elif state == 'absent':
            if not net:
                self.exit(changed=False)
            else:
                self.conn.network.delete_network(net['id'])
                self.exit(changed=True)


def main():
    module = NetworkModule()
    module()


if __name__ == '__main__':
    main()
