#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2018 Catalyst Cloud Ltd.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: lb_pool
short_description: Manage load-balancer pool in a OpenStack cloud.
author: OpenStack Ansible SIG
description:
  - Add, update or remove load-balancer pool from OpenStack cloud.
options:
  description:
    description:
      - A human-readable description for the load-balancer pool.
    type: str
  lb_algorithm:
    description:
      - The load balancing algorithm for the pool.
      - For example, I(lb_algorithm) could be C(LEAST_CONNECTIONS),
        C(ROUND_ROBIN), C(SOURCE_IP) or C(SOURCE_IP_PORT).
    default: ROUND_ROBIN
    type: str
  listener:
    description:
      - The name or id of the listener that this pool belongs to.
      - Either I(listener) or I(loadbalancer) must be specified for pool
        creation.
      - This attribute cannot be updated.
    type: str
  loadbalancer:
    description:
      - The name or id of the load balancer that this pool belongs to.
      - Either I(listener) or I(loadbalancer) must be specified for pool
        creation.
      - This attribute cannot be updated.
    type: str
  name:
    description:
      - Name that has to be given to the pool.
      - This attribute cannot be updated.
    required: true
    type: str
  protocol:
    description:
      - The protocol for the pool.
      - For example, I(protocol) could be C(HTTP), C(HTTPS), C(PROXY),
        C(PROXYV2), C(SCTP), C(TCP) and C(UDP).
      - This attribute cannot be updated.
    default: HTTP
    type: str
  state:
    description:
      - Should the resource be present or absent.
    choices: [present, absent]
    default: present
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
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
- name: Create a load-balancer pool
  openstack.cloud.lb_pool:
    cloud: mycloud
    lb_algorithm: ROUND_ROBIN
    loadbalancer: test-loadbalancer
    name: test-pool
    protocol: HTTP
    state: present

- name: Delete a load-balancer pool
  openstack.cloud.lb_pool:
    cloud: mycloud
    name: test-pool
    state: absent
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class LoadBalancerPoolModule(OpenStackModule):
    argument_spec = dict(
        description=dict(),
        lb_algorithm=dict(default='ROUND_ROBIN'),
        listener=dict(),
        loadbalancer=dict(),
        name=dict(required=True),
        protocol=dict(default='HTTP'),
        state=dict(default='present', choices=['absent', 'present']),
    )
    module_kwargs = dict(
        required_if=[
            ('state', 'present', ('listener', 'loadbalancer'), True),
        ],
        mutually_exclusive=[
            ('listener', 'loadbalancer')
        ],
        supports_check_mode=True,
    )

    def run(self):
        state = self.params['state']

        pool = self._find()

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, pool))

        if state == 'present' and not pool:
            # Create pool
            pool = self._create()
            self.exit_json(changed=True,
                           pool=pool.to_dict(computed=False))

        elif state == 'present' and pool:
            # Update pool
            update = self._build_update(pool)
            if update:
                pool = self._update(pool, update)

            self.exit_json(changed=bool(update),
                           pool=pool.to_dict(computed=False))

        elif state == 'absent' and pool:
            # Delete pool
            self._delete(pool)
            self.exit_json(changed=True)

        elif state == 'absent' and not pool:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, pool):
        update = {}

        non_updateable_keys = [k for k in ['protocol']
                               if self.params[k] is not None
                               and self.params[k] != pool[k]]

        listener_name_or_id = self.params['listener']
        if listener_name_or_id:
            listener = self.conn.load_balancer.find_listener(
                listener_name_or_id, ignore_missing=False)
            # Field listener_id is not returned from self.conn.load_balancer.\
            # find_listener() so use listeners instead.
            if pool['listeners'] != [dict(id=listener.id)]:
                non_updateable_keys.append('listener_id')

        loadbalancer_name_or_id = self.params['loadbalancer']
        if loadbalancer_name_or_id:
            loadbalancer = self.conn.load_balancer.find_load_balancer(
                loadbalancer_name_or_id, ignore_missing=False)
            # Field load_balancer_id is not returned from self.conn.\
            # load_balancer.find_load_balancer() so use load_balancers instead.
            if listener['load_balancers'] != [dict(id=loadbalancer.id)]:
                non_updateable_keys.append('loadbalancer_id')

        if non_updateable_keys:
            self.fail_json(msg='Cannot update parameters {0}'
                               .format(non_updateable_keys))

        attributes = dict((k, self.params[k])
                          for k in ['description', 'lb_algorithm']
                          if self.params[k] is not None
                          and self.params[k] != pool[k])

        if attributes:
            update['attributes'] = attributes

        return update

    def _create(self):
        kwargs = dict((k, self.params[k])
                      for k in ['description', 'name', 'protocol',
                                'lb_algorithm']
                      if self.params[k] is not None)

        listener_name_or_id = self.params['listener']
        if listener_name_or_id:
            listener = self.conn.load_balancer.find_listener(
                listener_name_or_id, ignore_missing=False)
            kwargs['listener_id'] = listener.id

        loadbalancer_name_or_id = self.params['loadbalancer']
        if loadbalancer_name_or_id:
            loadbalancer = self.conn.load_balancer.find_load_balancer(
                loadbalancer_name_or_id, ignore_missing=False)
            kwargs['loadbalancer_id'] = loadbalancer.id

        pool = self.conn.load_balancer.create_pool(**kwargs)

        if self.params['wait']:
            pool = self.sdk.resource.wait_for_status(
                self.conn.load_balancer, pool,
                status='active',
                failures=['error'],
                wait=self.params['timeout'],
                attribute='provisioning_status')

        return pool

    def _delete(self, pool):
        self.conn.load_balancer.delete_pool(pool.id)

        if self.params['wait']:
            for count in self.sdk.utils.iterate_timeout(
                timeout=self.params['timeout'],
                message="Timeout waiting for load-balancer pool to be absent"
            ):
                if self.conn.load_balancer.\
                   find_pool(pool.id) is None:
                    break

    def _find(self):
        name = self.params['name']
        return self.conn.load_balancer.find_pool(name_or_id=name)

    def _update(self, pool, update):
        attributes = update.get('attributes')
        if attributes:
            pool = self.conn.load_balancer.update_pool(pool.id, **attributes)

        if self.params['wait']:
            pool = self.sdk.resource.wait_for_status(
                self.conn.load_balancer, pool,
                status='active',
                failures=['error'],
                wait=self.params['timeout'],
                attribute='provisioning_status')

        return pool

    def _will_change(self, state, pool):
        if state == 'present' and not pool:
            return True
        elif state == 'present' and pool:
            return bool(self._build_update(pool))
        elif state == 'absent' and pool:
            return True
        else:
            # state == 'absent' and not pool:
            return False


def main():
    module = LoadBalancerPoolModule()
    module()


if __name__ == "__main__":
    main()
