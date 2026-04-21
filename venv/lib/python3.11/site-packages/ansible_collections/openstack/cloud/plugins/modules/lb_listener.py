#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2018 Catalyst Cloud Ltd.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: lb_listener
short_description: Manage load-balancer listener in a OpenStack cloud
author: OpenStack Ansible SIG
description:
  - Add, update or remove listener from OpenStack load-balancer.
options:
  default_tls_container_ref:
    description:
      - A URI to a key manager service secrets container with TLS secrets.
    type: str
  description:
    description:
      - A human-readable description for the load-balancer listener.
    type: str
  is_admin_state_up:
    description:
      - The administrative state of the listener, which is up or down.
    type: bool
  load_balancer:
    description:
      - The name or id of the load-balancer that this listener belongs to.
      - Required when I(state) is C(present).
      - This attribute cannot be updated.
    type: str
    aliases: ['loadbalancer']
  name:
    description:
      - Name that has to be given to the listener.
      - This attribute cannot be updated.
    required: true
    type: str
  protocol:
    description:
      - The protocol for the listener.
      - For example, I(protocol) could be C(HTTP), C(HTTPS), C(TCP),
        C(TERMINATED_HTTPS), C(UDP), C(SCTP) or C(PROMETHEUS).
      - This attribute cannot be updated.
    default: HTTP
    type: str
  protocol_port:
    description:
      - The protocol port number for the listener.
      - This attribute cannot be updated.
    type: int
  sni_container_refs:
    description:
      - A list of URIs to the key manager service secrets containers with TLS
        secrets.
    type: list
    elements: str
  state:
    description:
      - Should the resource be present or absent.
    choices: [present, absent]
    default: present
    type: str
  timeout_client_data:
    description:
      - Client inactivity timeout in milliseconds.
    type: int
  timeout_member_data:
    description:
      - Member inactivity timeout in milliseconds.
    type: int
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
listener:
  description: Dictionary describing the listener.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    allowed_cidrs:
      description: List of IPv4 or IPv6 CIDRs.
      type: list
    alpn_protocols:
      description: List of ALPN protocols.
      type: list
    connection_limit:
      description: The maximum number of connections permitted for this load
                   balancer.
      type: str
    created_at:
      description: Timestamp when the listener was created.
      type: str
    default_pool:
      description: Default pool to which the requests will be routed.
      type: str
    default_pool_id:
      description: ID of default pool. Must have compatible protocol with
                   listener.
      type: str
    default_tls_container_ref:
      description: A reference to a container of TLS secrets.
      type: str
    description:
      description: The listener description.
      type: str
      sample: "description"
    id:
      description: Unique UUID.
      type: str
      sample: "39007a7e-ee4f-4d13-8283-b4da2e037c69"
    insert_headers:
      description: Dictionary of additional headers insertion into HTTP header.
      type: dict
    is_admin_state_up:
      description: The administrative state of the listener.
      type: bool
      sample: true
    l7_policies:
      description: A list of L7 policy objects.
      type: list
    load_balancer_id:
      description: The load balancer UUID this listener belongs to.
      type: str
      sample: "b32eef7e-d2a6-4ea4-a301-60a873f89b3b"
    load_balancers:
      description: A list of load balancer IDs.
      type: list
      sample: [{"id": "b32eef7e-d2a6-4ea4-a301-60a873f89b3b"}]
    name:
      description: Name given to the listener.
      type: str
      sample: "test"
    operating_status:
      description: The operating status of the listener.
      type: str
      sample: "ONLINE"
    project_id:
      description: The ID of the project owning this resource.
      type: str
    protocol:
      description: The protocol for the listener.
      type: str
      sample: "HTTP"
    protocol_port:
      description: The protocol port number for the listener.
      type: int
      sample: 80
    provisioning_status:
      description: The provisioning status of the listener.
      type: str
      sample: "ACTIVE"
    sni_container_refs:
      description: A list of references to TLS secrets.
      type: list
    tags:
      description: A list of associated tags.
      type: list
    timeout_client_data:
      description: Client inactivity timeout in milliseconds.
      type: int
      sample: 50000
    timeout_member_connect:
      description: Backend member connection timeout in milliseconds.
      type: int
    timeout_member_data:
      description: Member inactivity timeout in milliseconds.
      type: int
      sample: 50000
    timeout_tcp_inspect:
      description: Time, in milliseconds, to wait for additional TCP packets
                   for content inspection.
      type: int
    tls_ciphers:
      description: Stores a cipher string in OpenSSL format.
      type: str
    tls_versions:
      description: A list of TLS protocols to be used by the listener.
      type: list
    updated_at:
      description: Timestamp when the listener was last updated.
      type: str
'''

EXAMPLES = r'''
- name: Create a listener, wait for the loadbalancer to be active
  openstack.cloud.lb_listener:
    cloud: mycloud
    load_balancer: test-loadbalancer
    name: test-listener
    protocol: HTTP
    protocol_port: 8080
    state: present

- name: Delete a listener
  openstack.cloud.lb_listener:
    cloud: mycloud
    load_balancer: test-loadbalancer
    name: test-listener
    state: absent

- name: Create a listener, increase timeouts for connection persistence
  openstack.cloud.lb_listener:
    cloud: mycloud
    load_balancer: test-loadbalancer
    name: test-listener
    protocol: TCP
    protocol_port: 22
    state: present
    timeout_client_data: 1800000
    timeout_member_data: 1800000
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class LoadBalancerListenerModule(OpenStackModule):
    argument_spec = dict(
        default_tls_container_ref=dict(),
        description=dict(),
        is_admin_state_up=dict(type='bool'),
        load_balancer=dict(aliases=['loadbalancer']),
        name=dict(required=True),
        protocol=dict(default='HTTP'),
        protocol_port=dict(type='int'),
        sni_container_refs=dict(type='list', elements='str'),
        state=dict(default='present', choices=['absent', 'present']),
        timeout_client_data=dict(type='int'),
        timeout_member_data=dict(type='int'),
    )
    module_kwargs = dict(
        required_if=[
            ('state', 'present', ('load_balancer',)),
        ],
        supports_check_mode=True,
    )

    def run(self):
        state = self.params['state']

        listener = self._find()

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, listener))

        if state == 'present' and not listener:
            # Create listener
            listener = self._create()
            self.exit_json(changed=True,
                           rbac_listener=listener.to_dict(computed=False),
                           listener=listener.to_dict(computed=False))

        elif state == 'present' and listener:
            # Update listener
            update = self._build_update(listener)
            if update:
                listener = self._update(listener, update)

            self.exit_json(changed=bool(update),
                           rbac_listener=listener.to_dict(computed=False),
                           listener=listener.to_dict(computed=False))

        elif state == 'absent' and listener:
            # Delete listener
            self._delete(listener)
            self.exit_json(changed=True)

        elif state == 'absent' and not listener:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, listener):
        update = {}

        non_updateable_keys = [k for k in ['protocol', 'protocol_port']
                               if self.params[k] is not None
                               and self.params[k] != listener[k]]

        load_balancer_name_or_id = self.params['load_balancer']
        load_balancer = self.conn.load_balancer.find_load_balancer(
            load_balancer_name_or_id, ignore_missing=False)
        # Field load_balancer_id is not returned from self.conn.load_balancer.\
        # find_load_balancer() so use load_balancers instead.
        if listener['load_balancers'] != [dict(id=load_balancer.id)]:
            non_updateable_keys.append('load_balancer')

        if non_updateable_keys:
            self.fail_json(msg='Cannot update parameters {0}'
                               .format(non_updateable_keys))

        attributes = dict((k, self.params[k])
                          for k in ['default_tls_container_ref',
                                    'description',
                                    'is_admin_state_up',
                                    'sni_container_refs',
                                    'timeout_client_data',
                                    'timeout_member_data']
                          if self.params[k] is not None
                          and self.params[k] != listener[k])

        if attributes:
            update['attributes'] = attributes

        return update

    def _create(self):
        kwargs = dict((k, self.params[k])
                      for k in ['default_tls_container_ref', 'description',
                                'is_admin_state_up', 'name', 'protocol',
                                'protocol_port', 'sni_container_refs',
                                'timeout_client_data', 'timeout_member_data']
                      if self.params[k] is not None)

        load_balancer_name_or_id = self.params['load_balancer']
        load_balancer = self.conn.load_balancer.find_load_balancer(
            load_balancer_name_or_id, ignore_missing=False)
        kwargs['load_balancer_id'] = load_balancer.id

        listener = self.conn.load_balancer.create_listener(**kwargs)

        if self.params['wait']:
            self.conn.load_balancer.wait_for_load_balancer(
                listener.load_balancer_id,
                wait=self.params['timeout'])

        return listener

    def _delete(self, listener):
        self.conn.load_balancer.delete_listener(listener.id)

        if self.params['wait']:
            # Field load_balancer_id is not returned from self.conn.\
            # load_balancer.find_listener() so use load_balancers instead.
            if not listener.load_balancers \
               or len(listener.load_balancers) != 1:
                raise AssertionError("A single load-balancer is expected")

            self.conn.load_balancer.wait_for_load_balancer(
                listener.load_balancers[0]['id'],
                wait=self.params['timeout'])

    def _find(self):
        name = self.params['name']
        return self.conn.load_balancer.find_listener(name_or_id=name)

    def _update(self, listener, update):
        attributes = update.get('attributes')
        if attributes:
            listener = self.conn.load_balancer.update_listener(listener.id,
                                                               **attributes)

        if self.params['wait']:
            # Field load_balancer_id is not returned from self.conn.\
            # load_balancer.find_listener() so use load_balancers instead.
            if not listener.load_balancers \
               or len(listener.load_balancers) != 1:
                raise AssertionError("A single load-balancer is expected")

            self.conn.load_balancer.wait_for_load_balancer(
                listener.load_balancers[0]['id'],
                wait=self.params['timeout'])

        return listener

    def _will_change(self, state, listener):
        if state == 'present' and not listener:
            return True
        elif state == 'present' and listener:
            return bool(self._build_update(listener))
        elif state == 'absent' and listener:
            return True
        else:
            # state == 'absent' and not listener:
            return False


def main():
    module = LoadBalancerListenerModule()
    module()


if __name__ == "__main__":
    main()
