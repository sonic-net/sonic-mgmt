#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2018 Catalyst Cloud Ltd.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: lb_member
short_description: Manage members in a OpenStack load-balancer pool
author: OpenStack Ansible SIG
description:
   - Add, update or remove member from OpenStack load-balancer pool.
options:
  address:
    description:
      - The IP address of the member.
      - Required when I(state) is C(present).
      - This attribute cannot be updated.
    type: str
  monitor_address:
    description:
      - IP address used to monitor this member.
    type: str
  monitor_port:
    description:
      - Port used to monitor this member.
    type: int
  name:
    description:
      - Name that has to be given to the member.
    required: true
    type: str
  pool:
    description:
      - The name or id of the pool that this member belongs to.
      - This attribute cannot be updated.
    required: true
    type: str
  protocol_port:
    description:
      - The protocol port number for the member.
      - Required when I(state) is C(present).
      - This attribute cannot be updated.
    type: int
  state:
    description:
      - Should the resource be C(present) or C(absent).
    choices: [present, absent]
    default: present
    type: str
  subnet_id:
    description:
      - The subnet ID the member service is accessible from.
      - This attribute cannot be updated.
    type: str
  weight:
    description:
      - The weight of a member determines the portion of requests or
        connections it services compared to the other members of the pool.
      - For example, a member with a weight of 10 receives five times as many
        requests as a member with a weight of 2. A value of 0 means the member
        does not receive new connections but continues to service existing
        connections. A valid value is from 0 to 256.
      - "Octavia's default for I(weight) is C(1)."
    type: int
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
member:
  description: Dictionary describing the load-balancer pool member.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    address:
      description: The IP address of the backend member server.
      type: str
    backup:
      description: A bool value that indicates whether the member is a backup
                    or not. Backup members only receive traffic when all
                    non-backup members are down.
      type: bool
    created_at:
      description: Timestamp when the member was created.
      type: str
    id:
      description: Unique UUID.
      type: str
    is_admin_state_up:
      description: The administrative state of the member.
      type: bool
    monitor_address:
      description: IP address used to monitor this member.
      type: str
    monitor_port:
      description: Port used to monitor this member.
      type: int
    name:
      description: Name given to the member.
      type: str
    operating_status:
      description: Operating status of the member.
      type: str
    project_id:
      description: The ID of the project this member is associated with.
      type: str
    protocol_port:
      description: The protocol port number for the member.
      type: int
    provisioning_status:
      description: The provisioning status of the member.
      type: str
    subnet_id:
      description: The subnet ID the member service is accessible from.
      type: str
    tags:
      description: A list of associated tags.
      type: list
    updated_at:
      description: Timestamp when the member was last updated.
      type: str
    weight:
      description: A positive integer value that indicates the relative portion
                   of traffic that this member should receive from the pool.
                   For example, a member with a weight of 10 receives five
                   times as much traffic as a member with weight of 2.
      type: int
pool:
  description: Dictionary describing the load-balancer pool.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    alpn_protocols:
      description: List of ALPN protocols.
      type: list
    created_at:
      description: Timestamp when the pool was created.
      type: str
    description:
      description: The pool description.
      type: str
    health_monitor_id:
      description: Health Monitor ID.
      type: str
    id:
      description: Unique UUID.
      type: str
    is_admin_state_up:
      description: The administrative state of the pool.
      type: bool
    lb_algorithm:
      description: The load balancing algorithm for the pool.
      type: str
    listener_id:
      description: The listener ID the pool belongs to.
      type: str
    listeners:
      description: A list of listener IDs.
      type: list
    loadbalancer_id:
      description: The load balancer ID the pool belongs to. This field is set
                   when the pool does not belong to any listener in the load
                   balancer.
      type: str
    loadbalancers:
      description: A list of load balancer IDs.
      type: list
    members:
      description: A list of member IDs.
      type: list
    name:
      description: Name given to the pool.
      type: str
    operating_status:
      description: The operating status of the pool.
      type: str
    project_id:
      description: The ID of the project.
      type: str
    protocol:
      description: The protocol for the pool.
      type: str
    provisioning_status:
      description: The provisioning status of the pool.
      type: str
    session_persistence:
      description: A JSON object specifying the session persistence for the
                   pool.
      type: dict
    tags:
      description: A list of associated tags.
      type: list
    tls_ciphers:
      description: Stores a string of cipher strings in OpenSSL format.
      type: str
    tls_enabled:
      description: Use TLS for connections to backend member servers.
      type: bool
    tls_versions:
      description: A list of TLS protocol versions to be used in by the pool.
      type: list
    updated_at:
      description: Timestamp when the pool was updated.
      type: str
'''

EXAMPLES = r'''
- name: Create member in a load-balancer pool
  openstack.cloud.lb_member:
    address: 192.168.10.3
    cloud: mycloud
    name: test-member
    pool: test-pool
    protocol_port: 8080
    state: present

- name: Delete member from a load-balancer pool
  openstack.cloud.lb_member:
    cloud: mycloud
    name: test-member
    pool: test-pool
    state: absent
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class LoadBalancerMemberModule(OpenStackModule):
    argument_spec = dict(
        address=dict(),
        monitor_address=dict(),
        monitor_port=dict(type='int'),
        name=dict(required=True),
        pool=dict(required=True),
        protocol_port=dict(type='int'),
        state=dict(default='present', choices=['absent', 'present']),
        subnet_id=dict(),
        weight=dict(type='int'),
    )
    module_kwargs = dict(
        required_if=[
            ('state', 'present', ('address', 'protocol_port',)),
        ],
        supports_check_mode=True,
    )

    def run(self):
        state = self.params['state']

        member, pool = self._find()

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, member, pool))

        if state == 'present' and not member:
            # Create member
            member = self._create(pool)
            self.exit_json(changed=True,
                           member=member.to_dict(computed=False),
                           pool=pool.to_dict(computed=False))

        elif state == 'present' and member:
            # Update member
            update = self._build_update(member, pool)
            if update:
                member = self._update(member, pool, update)

            self.exit_json(changed=bool(update),
                           member=member.to_dict(computed=False),
                           pool=pool.to_dict(computed=False))

        elif state == 'absent' and member:
            # Delete member
            self._delete(member, pool)
            self.exit_json(changed=True)

        elif state == 'absent' and not member:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, member, pool):
        update = {}

        non_updateable_keys = [k for k in ['address', 'name', 'protocol_port',
                                           'subnet_id']
                               if self.params[k] is not None
                               and self.params[k] != member[k]]

        if non_updateable_keys:
            self.fail_json(msg='Cannot update parameters {0}'
                               .format(non_updateable_keys))

        attributes = dict((k, self.params[k])
                          for k in ['monitor_address', 'monitor_port',
                                    'weight']
                          if self.params[k] is not None
                          and self.params[k] != member[k])

        if attributes:
            update['attributes'] = attributes

        return update

    def _create(self, pool):
        kwargs = dict((k, self.params[k])
                      for k in ['address', 'monitor_address', 'monitor_port',
                                'name', 'protocol_port', 'subnet_id', 'weight']
                      if self.params[k] is not None)

        member = self.conn.load_balancer.create_member(pool.id, **kwargs)

        if self.params['wait']:
            member = self.sdk.resource.wait_for_status(
                self.conn.load_balancer, member,
                status='active',
                failures=['error'],
                wait=self.params['timeout'],
                attribute='provisioning_status')

        return member

    def _delete(self, member, pool):
        self.conn.load_balancer.delete_member(member.id, pool.id)

        if self.params['wait']:
            for count in self.sdk.utils.iterate_timeout(
                timeout=self.params['timeout'],
                message="Timeout waiting for load-balancer member to be absent"
            ):
                if self.conn.load_balancer.\
                   find_member(member.id, pool.id) is None:
                    break

    def _find(self):
        name = self.params['name']
        pool_name_or_id = self.params['pool']

        pool = self.conn.load_balancer.find_pool(name_or_id=pool_name_or_id,
                                                 ignore_missing=False)
        member = self.conn.load_balancer.find_member(name, pool.id)

        return member, pool

    def _update(self, member, pool, update):
        attributes = update.get('attributes')
        if attributes:
            member = self.conn.load_balancer.update_member(member.id, pool.id,
                                                           **attributes)
        if self.params['wait']:
            member = self.sdk.resource.wait_for_status(
                self.conn.load_balancer, member,
                status='active',
                failures=['error'],
                wait=self.params['timeout'],
                attribute='provisioning_status')

        return member

    def _will_change(self, state, member, pool):
        if state == 'present' and not member:
            return True
        elif state == 'present' and member:
            return bool(self._build_update(member, pool))
        elif state == 'absent' and member:
            return True
        else:
            # state == 'absent' and not member:
            return False


def main():
    module = LoadBalancerMemberModule()
    module()


if __name__ == "__main__":
    main()
