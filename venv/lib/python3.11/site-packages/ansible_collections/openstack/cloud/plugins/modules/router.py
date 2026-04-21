#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: router
short_description: Create or delete routers from OpenStack
author: OpenStack Ansible SIG
description:
   - Create or Delete routers from OpenStack. Although Neutron allows
     routers to share the same name, this module enforces name uniqueness
     to be more user friendly.
options:
    enable_snat:
      description:
        - Enable Source NAT (SNAT) attribute.
      type: bool
    external_fixed_ips:
      description:
        - The IP address parameters for the external gateway network. Each
          is a dictionary with the subnet name or ID (subnet) and the IP
          address to assign on the subnet (ip_address). If no IP is specified,
          one is automatically assigned from that subnet.
      type: list
      elements: dict
      suboptions:
        ip_address:
           description: The fixed IP address to attempt to allocate.
           type: str
           aliases: ['ip']
        subnet_id:
           description: The subnet to attach the IP address to.
           required: true
           type: str
           aliases: ['subnet']
    external_gateway_info:
      description:
       - Information about the router's external gateway
      type: dict
      suboptions:
        network:
          description:
            - Unique name or ID of the external gateway network.
            - required I(interfaces) or I(enable_snat) are provided.
          type: str
        enable_snat:
          description:
            - Unique name or ID of the external gateway network.
            - required I(interfaces) or I(enable_snat) are provided.
          type: bool
        external_fixed_ips:
          description:
            - The IP address parameters for the external gateway network. Each
              is a dictionary with the subnet name or ID (subnet) and the IP
              address to assign on the subnet (ip_address). If no IP is
              specified, one is automatically assigned from that subnet.
          type: list
          elements: dict
          suboptions:
            ip_address:
               description: The fixed IP address to attempt to allocate.
               type: str
               aliases: ['ip']
            subnet_id:
               description: The subnet to attach the IP address to.
               required: true
               type: str
               aliases: ['subnet']
    interfaces:
      description:
        - List of subnets to attach to the router internal interface. Default
          gateway associated with the subnet will be automatically attached
          with the router's internal interface.
          In order to provide an ip address different from the default
          gateway,parameters are passed as dictionary with keys as network
          name or ID (I(net)), subnet name or ID (I(subnet)) and the IP of
          port (I(portip)) from the network.
          User defined portip is often required when a multiple router need
          to be connected to a single subnet for which the default gateway has
          been already used.
      type: list
      elements: raw
    is_admin_state_up:
      description:
        - Desired admin state of the created or existing router.
      type: bool
      default: 'true'
      aliases: ['admin_state_up']
    name:
      description:
        - Name to be give to the router.
        - This router attribute cannot be updated.
      required: true
      type: str
    network:
      description:
        - Unique name or ID of the external gateway network.
        - Required if I(external_fixed_ips) or I(enable_snat) are provided.
        - This router attribute cannot be updated.
      type: str
    project:
      description:
        - Unique name or ID of the project.
        - This router attribute cannot be updated.
      type: str
    state:
      description:
        - Indicate desired state of the resource
      choices: ['present', 'absent']
      default: present
      type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
# Create a simple router, not attached to a gateway or subnets.
- openstack.cloud.router:
    cloud: mycloud
    state: present
    name: simple_router

# Create a router, not attached to a gateway or subnets for a given project.
- openstack.cloud.router:
    cloud: mycloud
    state: present
    name: simple_router
    project: myproj

# Creates a router attached to ext_network1 on an IPv4 subnet and with one
# internal subnet interface.
- openstack.cloud.router:
    cloud: mycloud
    state: present
    name: router1
    network: ext_network1
    external_fixed_ips:
      - subnet: public-subnet
        ip_address: 172.24.4.2
    interfaces:
      - private-subnet

# Create a router with two internal subnet interfaces and a user defined port
# ip and another with default gateway.
- openstack.cloud.router:
    cloud: mycloud
    state: present
    name: router2
    network: ext_network1
    interfaces:
      - net: private-net
        subnet: private-subnet
        portip: 10.1.1.10
      - project-subnet

# Create a router with two internal subnet interface. One with user defined
# port ip and and another with default gateway.
- openstack.cloud.router:
    cloud: mycloud
    state: present
    name: router2
    network: ext_network1
    interfaces:
      - net: private-net
        subnet: private-subnet
        portip: 10.1.1.10
      - project-subnet

# Create a router with two internal subnet interface. One with user defined
# port ip and and another  with default gateway.
- openstack.cloud.router:
    cloud: mycloud
    state: present
    name: router2
    network: ext_network1
    interfaces:
      - net: private-net
        subnet: private-subnet
        portip: 10.1.1.10
      - project-subnet

# Update existing router1 external gateway to include the IPv6 subnet.
# Note that since 'interfaces' is not provided, any existing internal
# interfaces on an existing router will be left intact.
- openstack.cloud.router:
    cloud: mycloud
    state: present
    name: router1
    network: ext_network1
    external_fixed_ips:
      - subnet: public-subnet
        ip_address: 172.24.4.2
      - subnet: ipv6-public-subnet
        ip_address: 2001:db8::3

# Delete router1
- openstack.cloud.router:
    cloud: mycloud
    state: absent
    name: router1
'''

RETURN = '''
router:
    description: Dictionary describing the router.
    returned: On success when I(state) is 'present'
    type: dict
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
            sample: |
                {
                    "enable_snat": true,
                    "external_fixed_ips": [
                        {
                           "ip_address": "10.6.6.99",
                           "subnet_id": "4272cb52-a456-4c20-8f3c-c26024ecfa81"
                        }
                    ]
                }
        flavor_id:
            description: ID of the flavor of the router
            returned: success
            type: str
        id:
            description: Unique UUID.
            returned: success
            type: str
            sample: "474acfe5-be34-494c-b339-50f06aa143e4"
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
            sample: "router1"
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
            sample: "ACTIVE"
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
from collections import defaultdict


class RouterModule(OpenStackModule):

    external_fixed_ips_spec = dict(
        type='list',
        elements='dict',
        options=dict(
            ip_address=dict(aliases=["ip"]),
            subnet_id=dict(required=True, aliases=["subnet"]),
        ))

    argument_spec = dict(
        enable_snat=dict(type='bool'),
        external_fixed_ips=external_fixed_ips_spec,
        external_gateway_info=dict(type='dict', options=dict(
            network=dict(),
            enable_snat=dict(type='bool'),
            external_fixed_ips=external_fixed_ips_spec,
        )),
        interfaces=dict(type='list', elements='raw'),
        is_admin_state_up=dict(type='bool',
                               default=True,
                               aliases=['admin_state_up']),
        name=dict(required=True),
        network=dict(),
        project=dict(),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = dict(
        mutually_exclusive=[
            ('external_gateway_info', 'network'),
            ('external_gateway_info', 'external_fixed_ips'),
            ('external_gateway_info', 'enable_snat'),
        ],
        required_by={
            'external_fixed_ips': 'network',
            'enable_snat': 'network',
        },
    )

    def _needs_update(self, router, kwargs, external_fixed_ips, to_add,
                      to_remove, missing_port_ids):
        """Decide if the given router needs an update."""
        if router['is_admin_state_up'] != self.params['is_admin_state_up']:
            return True

        cur_ext_gw_info = router['external_gateway_info']
        if 'external_gateway_info' in kwargs:
            if cur_ext_gw_info is None:
                # added external gateway info
                return True
            update = kwargs['external_gateway_info']
            for attr in ('enable_snat', 'network_id'):
                if attr in update and cur_ext_gw_info[attr] != update[attr]:
                    return True

        cur_ext_gw_info = router['external_gateway_info']
        cur_ext_fips = (cur_ext_gw_info or {}) \
            .get('external_fixed_ips', [])

        # map of external fixed ip subnets to addresses
        cur_fip_map = defaultdict(set)
        for p in cur_ext_fips:
            if 'ip_address' in p:
                cur_fip_map[p['subnet_id']].add(p['ip_address'])
        req_fip_map = defaultdict(set)
        if external_fixed_ips is not None:
            # User passed expected external_fixed_ips configuration.
            # Build map of requested ips/subnets.
            for p in external_fixed_ips:
                if 'ip_address' in p:
                    req_fip_map[p['subnet_id']].add(p['ip_address'])
                elif p['subnet_id'] in cur_fip_map:
                    # handle idempotence of updating with no explicit ip
                    req_fip_map[p['subnet_id']].update(
                        cur_fip_map[p['subnet_id']])

            # Check if external ip addresses need to be added
            for fip in external_fixed_ips:
                subnet = fip['subnet_id']
                ip = fip.get('ip_address', None)
                if subnet in cur_fip_map:
                    if ip is not None and ip not in cur_fip_map[subnet]:
                        # mismatching ip for subnet
                        return True
                else:
                    # adding ext ip with subnet 'subnet'
                    return True

            # Check if external ip addresses need to be removed.
            for fip in cur_ext_fips:
                subnet = fip['subnet_id']
                ip = fip['ip_address']
                if subnet in req_fip_map:
                    if ip not in req_fip_map[subnet]:
                        # removing ext ip with subnet (ip clash)
                        return True
                else:
                    # removing ext ip with subnet
                    return True

        # Check if internal interfaces need update
        if to_add or to_remove or missing_port_ids:
            # need to change interfaces
            return True

        return False

    def _build_kwargs(self, router, network, ext_fixed_ips):
        kwargs = {
            'is_admin_state_up': self.params['is_admin_state_up'],
        }

        if not router:
            kwargs['name'] = self.params['name']
        # We cannot update a router name because name is used to find routers
        # by name so only any router with an already matching name will be
        # considered for updates

        external_gateway_info = {}
        if network:
            external_gateway_info['network_id'] = network.id
            # can't send enable_snat unless we have a network
            if self.params['enable_snat'] is not None:
                external_gateway_info['enable_snat'] = \
                    self.params['enable_snat']
        if ext_fixed_ips:
            external_gateway_info['external_fixed_ips'] = ext_fixed_ips
        if external_gateway_info:
            kwargs['external_gateway_info'] = external_gateway_info

        if 'external_fixed_ips' not in external_gateway_info:
            # no external fixed ips requested

            # get current external fixed ips
            curr_ext_gw_info = \
                router['external_gateway_info'] if router else None
            curr_ext_fixed_ips = \
                curr_ext_gw_info.get('external_fixed_ips', []) \
                if curr_ext_gw_info else []

            if len(curr_ext_fixed_ips) > 1:
                # but router has several external fixed ips
                # keep first external fixed ip only
                external_gateway_info['external_fixed_ips'] = [
                    curr_ext_fixed_ips[0]]

        return kwargs

    def _build_router_interface_config(self, filters):
        # Undefine external_fixed_ips to have possibility to unset them
        external_fixed_ips = None
        internal_ports_missing = []
        internal_ifaces = []

        # Build external interface configuration
        ext_fixed_ips = None
        if self.params['external_gateway_info']:
            ext_fixed_ips = self.params['external_gateway_info'] \
                .get('external_fixed_ips')
        ext_fixed_ips = ext_fixed_ips or self.params['external_fixed_ips']
        if ext_fixed_ips:
            # User passed external_fixed_ips configuration. Initialize ips list
            external_fixed_ips = []
            for iface in ext_fixed_ips:
                subnet = self.conn.network.find_subnet(
                    iface['subnet_id'], ignore_missing=False, **filters)
                fip = dict(subnet_id=subnet.id)
                if iface.get('ip_address', None) is not None:
                    fip['ip_address'] = iface['ip_address']
                external_fixed_ips.append(fip)

        # Build internal interface configuration
        if self.params['interfaces']:
            internal_ips = []
            for iface in self.params['interfaces']:
                if isinstance(iface, str):
                    subnet = self.conn.network.find_subnet(
                        iface, ignore_missing=False, **filters)
                    internal_ifaces.append(dict(subnet_id=subnet.id))

                elif isinstance(iface, dict):
                    subnet = self.conn.network.find_subnet(
                        iface['subnet'], ignore_missing=False, **filters)

                    # TODO: We allow passing a subnet without specifing a
                    #       network in case iface is a string, hence we
                    #       should allow to omit the network here as well.
                    if 'net' not in iface:
                        self.fail(
                            "Network name missing from interface definition")
                    net = self.conn.network.find_network(iface['net'],
                                                         ignore_missing=False)

                    if 'portip' not in iface:
                        # portip not set, add any ip from subnet
                        internal_ifaces.append(dict(subnet_id=subnet.id))
                    elif not iface['portip']:
                        # portip is set but has invalid value
                        self.fail(msg='put an ip in portip or remove it'
                                  'from list to assign default port to router')
                    else:
                        # portip has valid value
                        # look for ports whose fixed_ips.ip_address matchs
                        # portip
                        portip = iface['portip']
                        port_kwargs = ({'network_id': net.id}
                                       if net is not None else {})
                        existing_ports = self.conn.network.ports(**port_kwargs)
                        for port in existing_ports:
                            for fip in port['fixed_ips']:
                                if (fip['subnet_id'] != subnet.id
                                   or fip['ip_address'] != portip):
                                    continue
                                # portip exists in net already
                                internal_ips.append(fip['ip_address'])
                                internal_ifaces.append(
                                    dict(port_id=port.id,
                                         subnet_id=subnet.id,
                                         ip_address=portip))
                        if portip not in internal_ips:
                            # No port with portip exists
                            # hence create a new port
                            internal_ports_missing.append({
                                'network_id': subnet.network_id,
                                'fixed_ips': [{'ip_address': portip,
                                               'subnet_id': subnet.id}]
                            })

        return {
            'external_fixed_ips': external_fixed_ips,
            'internal_ports_missing': internal_ports_missing,
            'internal_ifaces': internal_ifaces,
        }

    def _update_ifaces(self, router, to_add, to_remove, missing_ports):
        for port in to_remove:
            self.conn.network.remove_interface_from_router(
                router, port_id=port.id)
        # create ports that are missing
        for port in missing_ports:
            p = self.conn.network.create_port(**port)
            if p:
                to_add.append(dict(port_id=p.id))
        for iface in to_add:
            self.conn.network.add_interface_to_router(router, **iface)

    def _get_external_gateway_network_name(self):
        network_name_or_id = self.params['network']
        if self.params['external_gateway_info']:
            network_name_or_id = \
                self.params['external_gateway_info']['network']
        return network_name_or_id

    def _get_port_changes(self, router, ifs_cfg):
        requested_subnet_ids = [iface['subnet_id'] for iface
                                in ifs_cfg['internal_ifaces']]

        router_ifs_internal = []
        if router:
            router_ifs_internal = self.conn.list_router_interfaces(
                router, 'internal')

        existing_subnet_ips = {}
        for iface in router_ifs_internal:
            if 'fixed_ips' not in iface:
                continue
            for fip in iface['fixed_ips']:
                existing_subnet_ips[fip['subnet_id']] = (fip['ip_address'],
                                                         iface)

        obsolete_subnet_ids = (set(existing_subnet_ips.keys())
                               - set(requested_subnet_ids))

        internal_ifaces = ifs_cfg['internal_ifaces']
        to_add = []
        to_remove = []
        for iface in internal_ifaces:
            subnet_id = iface['subnet_id']
            if subnet_id not in existing_subnet_ips:
                iface.pop('ip_address', None)
                to_add.append(iface)
                continue
            ip, existing_port = existing_subnet_ips[subnet_id]
            if 'ip_address' in iface and ip != iface['ip_address']:
                # Port exists for subnet but has the wrong ip. Schedule it for
                # deletion
                to_remove.append(existing_port)

        for port in router_ifs_internal:
            if 'fixed_ips' not in port:
                continue
            if any(fip['subnet_id'] in obsolete_subnet_ids
                   for fip in port['fixed_ips']):
                to_remove.append(port)
        return dict(to_add=to_add, to_remove=to_remove,
                    router_ifs_internal=router_ifs_internal)

    def run(self):
        state = self.params['state']
        name = self.params['name']
        network_name_or_id = self._get_external_gateway_network_name()
        project_name_or_id = self.params['project']

        if self.params['external_fixed_ips'] and not network_name_or_id:
            self.fail(
                msg='network is required when supplying external_fixed_ips')

        query_filters = {}
        project = None
        project_id = None
        if project_name_or_id is not None:
            project = self.conn.identity.find_project(project_name_or_id,
                                                      ignore_missing=False)
            project_id = project['id']
            query_filters['project_id'] = project_id

        router = self.conn.network.find_router(name, **query_filters)
        network = None
        if network_name_or_id:
            # First try to find a network in the specified project.
            network = self.conn.network.find_network(network_name_or_id,
                                                     **query_filters)
            if not network:
                # Fall back to a global search for the network.
                network = self.conn.network.find_network(network_name_or_id,
                                                         ignore_missing=False)

        # Validate and cache the subnet IDs so we can avoid duplicate checks
        # and expensive API calls.
        router_ifs_cfg = self._build_router_interface_config(query_filters)

        missing_internal_ports = router_ifs_cfg['internal_ports_missing']

        port_changes = self._get_port_changes(router, router_ifs_cfg)
        to_add = port_changes['to_add']
        to_remove = port_changes['to_remove']
        router_ifs_internal = port_changes['router_ifs_internal']

        external_fixed_ips = router_ifs_cfg['external_fixed_ips']

        if self.ansible.check_mode:
            # Check if the system state would be changed
            if state == 'absent' and router:
                changed = True
            elif state == 'absent' and not router:
                changed = False
            elif state == 'present' and not router:
                changed = True
            else:  # if state == 'present' and router
                kwargs = self._build_kwargs(router, network,
                                            external_fixed_ips)
                changed = self._needs_update(
                    router, kwargs, external_fixed_ips, to_add, to_remove,
                    missing_internal_ports)
            self.exit_json(changed=changed)

        if state == 'present':
            changed = False
            external_fixed_ips = router_ifs_cfg['external_fixed_ips']
            internal_ifaces = router_ifs_cfg['internal_ifaces']
            kwargs = self._build_kwargs(router, network,
                                        external_fixed_ips)

            if not router:
                changed = True

                if project_id:
                    kwargs['project_id'] = project_id
                router = self.conn.network.create_router(**kwargs)

                self._update_ifaces(router, internal_ifaces, [],
                                    missing_internal_ports)

            else:

                if self._needs_update(router, kwargs, external_fixed_ips,
                                      to_add, to_remove,
                                      missing_internal_ports):
                    changed = True
                    router = self.conn.network.update_router(router, **kwargs)

                    if to_add or to_remove or missing_internal_ports:
                        self._update_ifaces(router, to_add, to_remove,
                                            missing_internal_ports)

            self.exit_json(changed=changed,
                           router=router.to_dict(computed=False))

        elif state == 'absent':
            if not router:
                self.exit_json(changed=False)
            else:
                # We need to detach all internal interfaces on a router
                # before we will be allowed to delete it. Deletion can
                # still fail if e.g. floating ips are attached to the
                # router.
                for port in router_ifs_internal:
                    self.conn.network.remove_interface_from_router(
                        router, port_id=port['id'])
                self.conn.network.delete_router(router)
                self.exit_json(changed=True)


def main():
    module = RouterModule()
    module()


if __name__ == '__main__':
    main()
