#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2018 Catalyst Cloud Ltd.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: loadbalancer
short_description: Manage Octavia load-balancer in an OpenStack cloud
author: OpenStack Ansible SIG
description:
  - Add, update or remove Octavia load-balancer from OpenStack cloud.
options:
  assign_floating_ip:
    description:
      - Allocate floating ip address and associate with the VIP automatically.
      - Deprecated, use M(openstack.cloud.floating_ip) instead.
    type: bool
    default: false
    aliases: ['auto_public_ip']
  delete_floating_ip:
    description:
      - When I(state) is C(present) and I(delete_floating_ip) is C(true), then
        any floating ip address associated with the VIP will be deleted.
      - When I(state) is C(absent) and I(delete_floating_ip) is C(true), then
        any floating ip address associated with the VIP will be deleted along
        with the load balancer.
      - Deprecated, use M(openstack.cloud.floating_ip) instead.
    type: bool
    default: false
    aliases: ['delete_public_ip']
  description:
    description:
      - A human-readable description for the load-balancer.
    type: str
  flavor:
    description:
      - The flavor of the load balancer.
      - This attribute cannot be updated.
    type: str
  floating_ip_address:
    description:
      - Floating ip address aka public ip address associated with the VIP.
      - Deprecated, use M(openstack.cloud.floating_ip) instead.
    type: str
    aliases: ['public_ip_address']
  floating_ip_network:
    description:
      - Name or ID of a Neutron external network where floating ip address will
        be created on.
      - Deprecated, use M(openstack.cloud.floating_ip) instead.
    type: str
    aliases: ['public_network']
  name:
    description:
      - The name of the load balancer.
      - This attribute cannot be updated.
    required: true
    type: str
  state:
    description:
      - Should the resource be present or absent.
    choices: [present, absent]
    default: present
    type: str
  vip_address:
    description:
      - IP address of the load balancer virtual IP.
      - This attribute cannot be updated.
    type: str
  vip_network:
    description:
      - The name or id of the network for the virtual IP of the load balancer.
      - One of I(vip_network), I(vip_subnet), or I(vip_port) must be specified
        for creation.
      - This attribute cannot be updated.
    type: str
  vip_port:
    description:
      - The name or id of the load balancer virtual IP port. One of
      - One of I(vip_network), I(vip_subnet), or I(vip_port) must be specified
        for creation.
      - This attribute cannot be updated.
    type: str
  vip_subnet:
    description:
      - The name or id of the subnet for the virtual IP of the load balancer.
      - One of I(vip_network), I(vip_subnet), or I(vip_port) must be specified
        for creation.
      - This attribute cannot be updated.
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
floating_ip:
  description: Dictionary describing the floating ip address attached to the
               load-balancer.
  type: dict
  returned: On success when I(state) is C(present) and I(assign_floating_ip) is
            C(true).
  contains:
    created_at:
      description: Timestamp at which the floating IP was assigned.
      type: str
    description:
      description: The description of a floating IP.
      type: str
    dns_domain:
      description: The DNS domain.
      type: str
    dns_name:
      description: The DNS name.
      type: str
    fixed_ip_address:
      description: The fixed IP address associated with a floating IP address.
      type: str
    floating_ip_address:
      description: The IP address of a floating IP.
      type: str
    floating_network_id:
      description: The id of the network associated with a floating IP.
      type: str
    id:
      description: Id of the floating ip.
      type: str
    name:
      description: Name of the floating ip.
      type: str
    port_details:
      description: |
        The details of the port that this floating IP associates
        with. Present if C(fip-port-details) extension is loaded.
      type: dict
    port_id:
      description: The port ID floating ip associated with.
      type: str
    project_id:
      description: The ID of the project this floating IP is associated with.
      type: str
    qos_policy_id:
      description: The ID of the QoS policy attached to the floating IP.
      type: str
    revision_number:
      description: Revision number.
      type: str
    router_id:
      description: The id of the router floating ip associated with.
      type: str
    status:
      description: |
        The status of a floating IP, which can be 'ACTIVE' or 'DOWN'.
      type: str
    subnet_id:
      description: The id of the subnet the floating ip associated with.
      type: str
    tags:
      description: List of tags.
      type: list
      elements: str
    updated_at:
      description: Timestamp at which the floating IP was last updated.
      type: str
load_balancer:
  description: Dictionary describing the load-balancer.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    additional_vips:
      description: Additional VIPs.
      type: str
    availability_zone:
      description: Name of the target Octavia availability zone.
      type: str
    created_at:
      description: Timestamp when the load balancer was created.
      type: str
    description:
      description: The load balancer description.
      type: str
    flavor_id:
      description: The load balancer flavor ID.
      type: str
    id:
      description: Unique UUID.
      type: str
    is_admin_state_up:
      description: The administrative state of the load balancer.
      type: bool
    listeners:
      description: The associated listener IDs, if any.
      type: list
    name:
      description: Name given to the load balancer.
      type: str
    operating_status:
      description: The operating status of the load balancer.
      type: str
    pools:
      description: The associated pool IDs, if any.
      type: list
    project_id:
      description: The ID of the project this load balancer is associated with.
      type: str
    provider:
      description: Provider name for the load balancer.
      type: str
    provisioning_status:
      description: The provisioning status of the load balancer.
      type: str
    tags:
      description: A list of associated tags.
      type: str
    updated_at:
      description: Timestamp when the load balancer was last updated.
      type: str
    vip_address:
      description: The load balancer virtual IP address.
      type: str
    vip_network_id:
      description: Network ID the load balancer virtual IP port belongs in.
      type: str
    vip_port_id:
      description: The load balancer virtual IP port ID.
      type: str
    vip_qos_policy_id:
      description: VIP qos policy id.
      type: str
    vip_subnet_id:
      description: Subnet ID the load balancer virtual IP port belongs in.
      type: str
'''

EXAMPLES = r'''
- name: Create a load balancer
  openstack.cloud.loadbalancer:
    cloud: devstack
    name: my_lb
    state: present
    vip_subnet: my_subnet

- name: Create another load balancer
  openstack.cloud.loadbalancer:
    cloud: devstack
    name: my_lb
    state: present
    vip_address: 192.168.0.11
    vip_network: my_network

- name: Delete a load balancer and all its related resources
  openstack.cloud.loadbalancer:
    cloud: devstack
    name: my_lb
    state: absent

- name: Delete a load balancer, its related resources and its floating ip
  openstack.cloud.loadbalancer:
    cloud: devstack
    delete_floating_ip: true
    name: my_lb
    state: absent
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class LoadBalancerModule(OpenStackModule):

    argument_spec = dict(
        assign_floating_ip=dict(default=False, type='bool',
                                aliases=['auto_public_ip']),
        delete_floating_ip=dict(default=False, type='bool',
                                aliases=['delete_public_ip']),
        description=dict(),
        flavor=dict(),
        floating_ip_address=dict(aliases=['public_ip_address']),
        floating_ip_network=dict(aliases=['public_network']),
        name=dict(required=True),
        state=dict(default='present', choices=['absent', 'present']),
        vip_address=dict(),
        vip_network=dict(),
        vip_port=dict(),
        vip_subnet=dict(),
    )
    module_kwargs = dict(
        required_if=[
            ('state', 'present', ('vip_network', 'vip_subnet', 'vip_port'),
             True)
        ],
        mutually_exclusive=[
            ('assign_floating_ip', 'delete_floating_ip'),
        ],
        supports_check_mode=True,
    )

    def run(self):
        state = self.params['state']

        load_balancer = self._find()

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, load_balancer))

        if state == 'present' and not load_balancer:
            # Create load_balancer
            load_balancer, floating_ip = self._create()
            self.exit_json(
                changed=True,
                load_balancer=load_balancer.to_dict(computed=False),
                **(dict(floating_ip=floating_ip.to_dict(computed=False))
                   if floating_ip is not None else dict()))

        elif state == 'present' and load_balancer:
            # Update load_balancer
            update, floating_ip = self._build_update(load_balancer)
            if update:
                load_balancer, floating_ip = self._update(load_balancer,
                                                          update)

            self.exit_json(
                changed=bool(update),
                load_balancer=load_balancer.to_dict(computed=False),
                **(dict(floating_ip=floating_ip.to_dict(computed=False))
                   if floating_ip is not None else dict()))

        elif state == 'absent' and load_balancer:
            # Delete load_balancer
            self._delete(load_balancer)
            self.exit_json(changed=True)

        elif state == 'absent' and not load_balancer:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, load_balancer):
        update = {}

        non_updateable_keys = [k for k in ['name', 'vip_address']
                               if self.params[k] is not None
                               and self.params[k] != load_balancer[k]]

        flavor_name_or_id = self.params['flavor']
        if flavor_name_or_id is not None:
            flavor = self.conn.load_balancer.find_flavor(
                flavor_name_or_id, ignore_missing=False)
            if load_balancer['flavor_id'] != flavor.id:
                non_updateable_keys.append('flavor_id')

        vip_network_name_or_id = self.params['vip_network']
        if vip_network_name_or_id is not None:
            network = self.conn.network.find_network(
                vip_network_name_or_id, ignore_missing=False)
            if load_balancer['vip_network_id'] != network.id:
                non_updateable_keys.append('vip_network_id')

        vip_subnet_name_or_id = self.params['vip_subnet']
        if vip_subnet_name_or_id is not None:
            subnet = self.conn.network.find_subnet(
                vip_subnet_name_or_id, ignore_missing=False)
            if load_balancer['vip_subnet_id'] != subnet.id:
                non_updateable_keys.append('vip_subnet_id')

        vip_port_name_or_id = self.params['vip_port']
        if vip_port_name_or_id is not None:
            port = self.conn.network.find_port(
                vip_port_name_or_id, ignore_missing=False)
            if load_balancer['vip_port_id'] != port.id:
                non_updateable_keys.append('vip_port_id')

        if non_updateable_keys:
            self.fail_json(msg='Cannot update parameters {0}'
                               .format(non_updateable_keys))

        attributes = dict((k, self.params[k])
                          for k in ['description']
                          if self.params[k] is not None
                          and self.params[k] != load_balancer[k])

        if attributes:
            update['attributes'] = attributes

        floating_ip, floating_ip_update = \
            self._build_update_floating_ip(load_balancer)

        return {**update, **floating_ip_update}, floating_ip

    def _build_update_floating_ip(self, load_balancer):
        assign_floating_ip = self.params['assign_floating_ip']
        delete_floating_ip = self.params['delete_floating_ip']

        floating_ip_address = self.params['floating_ip_address']
        if floating_ip_address is not None \
           and (not assign_floating_ip and not delete_floating_ip):
            self.fail_json(msg="assign_floating_ip or delete_floating_ip must"
                               " be true when floating_ip_address is set")

        floating_ip_network = self.params['floating_ip_network']
        if floating_ip_network is not None \
           and (not assign_floating_ip and not delete_floating_ip):
            self.fail_json(msg="assign_floating_ip or delete_floating_ip must"
                               " be true when floating_ip_network is set")

        ips = list(self.conn.network.ips(
            port_id=load_balancer.vip_port_id,
            fixed_ip_address=load_balancer.vip_address))

        if len(ips) > 1:
            self.fail_json(msg="Only a single floating ip address"
                               " per load-balancer is supported")

        if delete_floating_ip or not assign_floating_ip:
            if not ips:
                return None, {}

            if len(ips) != 1:
                raise AssertionError("A single floating ip is expected")

            ip = ips[0]

            return ip, {'delete_floating_ip': ip}

        # else assign_floating_ip

        if not ips:
            return None, dict(
                assign_floating_ip=dict(
                    floating_ip_address=floating_ip_address,
                    floating_ip_network=floating_ip_network))

        if len(ips) != 1:
            raise AssertionError("A single floating ip is expected")

        ip = ips[0]

        if floating_ip_network is not None:
            network = self.conn.network.find_network(floating_ip_network,
                                                     ignore_missing=False)
            if ip.floating_network_id != network.id:
                return ip, dict(
                    assign_floating_ip=dict(
                        floating_ip_address=floating_ip_address,
                        floating_ip_network=floating_ip_network),
                    delete_floating_ip=ip)

        if floating_ip_address is not None \
           and floating_ip_address != ip.floating_ip_address:
            return ip, dict(
                assign_floating_ip=dict(
                    floating_ip_address=floating_ip_address,
                    floating_ip_network=floating_ip_network),
                delete_floating_ip=ip)

        return ip, {}

    def _create(self):
        kwargs = dict((k, self.params[k])
                      for k in ['description', 'name', 'vip_address']
                      if self.params[k] is not None)

        flavor_name_or_id = self.params['flavor']
        if flavor_name_or_id is not None:
            flavor = self.conn.load_balancer.find_flavor(
                flavor_name_or_id, ignore_missing=False)
            kwargs['flavor_id'] = flavor.id

        vip_network_name_or_id = self.params['vip_network']
        if vip_network_name_or_id is not None:
            network = self.conn.network.find_network(
                vip_network_name_or_id, ignore_missing=False)
            kwargs['vip_network_id'] = network.id

        vip_subnet_name_or_id = self.params['vip_subnet']
        if vip_subnet_name_or_id is not None:
            subnet = self.conn.network.find_subnet(
                vip_subnet_name_or_id, ignore_missing=False)
            kwargs['vip_subnet_id'] = subnet.id

        vip_port_name_or_id = self.params['vip_port']
        if vip_port_name_or_id is not None:
            port = self.conn.network.find_port(
                vip_port_name_or_id, ignore_missing=False)
            kwargs['vip_port_id'] = port.id

        load_balancer = self.conn.load_balancer.create_load_balancer(**kwargs)

        if self.params['wait']:
            load_balancer = self.conn.load_balancer.wait_for_load_balancer(
                load_balancer.id,
                wait=self.params['timeout'])

        floating_ip, update = self._build_update_floating_ip(load_balancer)
        if update:
            load_balancer, floating_ip = \
                self._update_floating_ip(load_balancer, update)

        return load_balancer, floating_ip

    def _delete(self, load_balancer):
        if self.params['delete_floating_ip']:
            ips = list(self.conn.network.ips(
                port_id=load_balancer.vip_port_id,
                fixed_ip_address=load_balancer.vip_address))
        else:
            ips = []

        # With cascade=False the deletion of load-balancer
        # would always fail if there are sub-resources.
        self.conn.load_balancer.delete_load_balancer(load_balancer.id,
                                                     cascade=True)

        if self.params['wait']:
            for count in self.sdk.utils.iterate_timeout(
                timeout=self.params['timeout'],
                message="Timeout waiting for load-balancer to be absent"
            ):
                if self.conn.load_balancer.\
                   find_load_balancer(load_balancer.id) is None:
                    break

        for ip in ips:
            self.conn.network.delete_ip(ip)

    def _find(self):
        name = self.params['name']
        return self.conn.load_balancer.find_load_balancer(name_or_id=name)

    def _update(self, load_balancer, update):
        attributes = update.get('attributes')
        if attributes:
            load_balancer = \
                self.conn.load_balancer.update_load_balancer(load_balancer.id,
                                                             **attributes)

        if self.params['wait']:
            load_balancer = self.conn.load_balancer.wait_for_load_balancer(
                load_balancer.id,
                wait=self.params['timeout'])

        load_balancer, floating_ip = \
            self._update_floating_ip(load_balancer, update)

        return load_balancer, floating_ip

    def _update_floating_ip(self, load_balancer, update):
        floating_ip = None
        delete_floating_ip = update.get('delete_floating_ip')
        if delete_floating_ip:
            self.conn.network.delete_ip(delete_floating_ip.id)

        assign_floating_ip = update.get('assign_floating_ip')
        if assign_floating_ip:
            floating_ip_address = assign_floating_ip['floating_ip_address']
            floating_ip_network = assign_floating_ip['floating_ip_network']

            if floating_ip_network is not None:
                network = self.conn.network.find_network(floating_ip_network,
                                                         ignore_missing=False)
            else:
                network = None

            if floating_ip_address is not None:
                kwargs = ({'floating_network_id': network.id}
                          if network is not None else {})
                ip = self.conn.network.find_ip(floating_ip_address, **kwargs)
            else:
                ip = None

            if ip:
                if ip['port_id'] is not None:
                    self.fail_json(
                        msg="Floating ip {0} is associated to another fixed ip"
                            " address {1} already".format(
                                ip.floating_ip_address, ip.fixed_ip_address))

                # Associate floating ip
                floating_ip = self.conn.network.update_ip(
                    ip.id, fixed_ip_address=load_balancer.vip_address,
                    port_id=load_balancer.vip_port_id)

            elif floating_ip_address:  # and not ip
                # Create new floating ip
                kwargs = ({'floating_network_id': network.id}
                          if network is not None else {})
                floating_ip = self.conn.network.create_ip(
                    fixed_ip_address=load_balancer.vip_address,
                    floating_ip_address=floating_ip_address,
                    port_id=load_balancer.vip_port_id,
                    **kwargs)

            elif network:
                # List disassociated floating ips on network
                ips = [ip
                       for ip in
                       self.conn.network.ips(floating_network_id=network.id)
                       if ip['port_id'] is None]
                if ips:
                    # Associate first disassociated floating ip
                    ip = ips[0]
                    floating_ip = self.conn.network.update_ip(
                        ip.id, fixed_ip_address=load_balancer.vip_address,
                        port_id=load_balancer.vip_port_id)
                else:
                    # No disassociated floating ips
                    # Create new floating ip on network
                    floating_ip = self.conn.network.create_ip(
                        fixed_ip_address=load_balancer.vip_address,
                        floating_network_id=network.id,
                        port_id=load_balancer.vip_port_id)

            else:
                # Find disassociated floating ip
                ip = self.conn.network.find_available_ip()

                if ip:
                    # Associate disassociated floating ip
                    floating_ip = self.conn.network.update_ip(
                        ip.id, fixed_ip_address=load_balancer.vip_address,
                        port_id=load_balancer.vip_port_id)
                else:
                    # Create new floating ip
                    floating_ip = self.conn.network.create_ip(
                        fixed_ip_address=load_balancer.vip_address,
                        port_id=load_balancer.vip_port_id)

        return load_balancer, floating_ip

    def _will_change(self, state, load_balancer):
        if state == 'present' and not load_balancer:
            return True
        elif state == 'present' and load_balancer:
            return bool(self._build_update(load_balancer)[0])
        elif state == 'absent' and load_balancer:
            return True
        else:
            # state == 'absent' and not load_balancer:
            return False


def main():
    module = LoadBalancerModule()
    module()


if __name__ == "__main__":
    main()
