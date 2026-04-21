#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 Jesper Schmitz Mouridsen.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: lb_health_monitor
author: OpenStack Ansible SIG
short_description: Manage health monitor in a OpenStack load-balancer pool
description:
  - Add, update or remove health monitor from a load-balancer pool in OpenStack
    cloud.
options:
  delay:
    description:
      - The interval, in seconds, between health checks.
      - Required when I(state) is C(present).
    type: int
  expected_codes:
    description:
      - The list of HTTP status codes expected in response from the member to
        declare it healthy. Specify one of the following values.
      - For example, I(expected_codes) could be a single value, such as C(200),
        a list, such as C(200, 202) or a range, such as C(200-204).
      - "Octavia's default for I(expected_codes) is C(200)."
    type: str
  health_monitor_timeout:
    description:
      - The time, in seconds, after which a health check times out.
      - Must be less than I(delay).
      - Required when I(state) is C(present).
    type: int
    aliases: ['resp_timeout']
  http_method:
    description:
      - The HTTP method that the health monitor uses for requests.
      - For example, I(http_method) could be C(CONNECT), C(DELETE), C(GET),
        C(HEAD), C(OPTIONS), C(PATCH), C(POST), C(PUT), or C(TRACE).
      - "Octavia's default for I(http_method) is C(GET)."
    type: str
  is_admin_state_up:
    description:
      - Whether the health monitor is up or down.
    type: bool
    aliases: ['admin_state_up']
  max_retries:
    description:
      - The number of successful checks before changing the operating status
        of the member to ONLINE.
      - Required when I(state) is C(present).
    type: int
  max_retries_down:
    description:
      - The number of allowed check failures before changing the operating
        status of the member to ERROR. A valid value is from 1 to 10.
    type: int
  name:
    description:
      - Name that has to be given to the health monitor.
      - This attribute cannot be updated.
    type: str
    required: true
  pool:
    description:
      - The pool name or id to monitor by the health monitor.
      - Required when I(state) is C(present).
      - This attribute cannot be updated.
    type: str
  state:
    description:
      - Should the resource be present or absent.
    choices: [present, absent]
    default: present
    type: str
  type:
    default: HTTP
    description:
      - The type of health monitor.
      - For example, I(type) could be C(HTTP), C(HTTPS), C(PING), C(SCTP),
        C(TCP), C(TLS-HELLO) or C(UDP-CONNECT).
      - This attribute cannot be updated.
    type: str
  url_path:
    description:
      - The HTTP URL path of the request sent by the monitor to test the health
        of a backend member.
      - Must be a string that begins with a forward slash (C(/)).
      - "Octavia's default URL path is C(/)."
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
health_monitor:
  description: Dictionary describing the load-balancer health monitor.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    created_at:
      description: The UTC date and timestamp when the resource was created.
      type: str
    delay:
      description: The time, in seconds, between sending probes to members.
      type: int
    expected_codes:
      description: The list of HTTP status codes expected in response from the
                   member to declare it healthy.
      type: str
    http_method:
      description: The HTTP method that the health monitor uses for requests.
      type: str
    id:
      description: The health monitor UUID.
      type: str
    is_admin_state_up:
      description: The administrative state of the resource.
      type: bool
    max_retries:
      description: The number of successful checks before changing the
                   operating status of the member to ONLINE.
      type: int
    max_retries_down:
      description: The number of allowed check failures before changing the
                   operating status of the member to ERROR.
      type: int
    name:
      description: Human-readable name of the resource.
      type: str
    operating_status:
      description: The operating status of the resource.
      type: str
    pool_id:
      description: The id of the pool.
      type: str
    pools:
      description: List of associated pool ids.
      type: list
    project_id:
      description: The ID of the project owning this resource.
      type: str
    provisioning_status:
      description: The provisioning status of the resource.
      type: str
    tags:
      description: A list of associated tags.
      type: list
    timeout:
      description: The maximum time, in seconds, that a monitor waits to
                   connect before it times out.
      type: int
    type:
      description: The type of health monitor.
      type: str
    updated_at:
      description: The UTC date and timestamp when the resource was last
                   updated.
      type: str
    url_path:
      description: The HTTP URL path of the request sent by the monitor to
                   test the health of a backend member.
      type: str
'''

EXAMPLES = r'''
- name: Create a load-balancer health monitor
  openstack.cloud.lb_health_monitor:
    cloud: devstack
    delay: 10
    expected_codes: '200'
    health_monitor_timeout: 5
    http_method: GET
    is_admin_state_up: true
    max_retries: 3
    max_retries_down: 4
    name: healthmonitor01
    pool: lb_pool
    state: present
    url_path: '/status'

- name: Delete a load-balancer health monitor
  openstack.cloud.lb_health_monitor:
    cloud: devstack
    name: healthmonitor01
    state: absent
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class LoadBalancerHealthMonitorModule(OpenStackModule):

    argument_spec = dict(
        delay=dict(type='int'),
        expected_codes=dict(),
        health_monitor_timeout=dict(type='int', aliases=['resp_timeout']),
        http_method=dict(),
        is_admin_state_up=dict(type='bool', aliases=['admin_state_up']),
        max_retries=dict(type='int'),
        max_retries_down=dict(type='int'),
        name=dict(required=True),
        pool=dict(),
        state=dict(default='present', choices=['absent', 'present']),
        type=dict(default='HTTP'),
        url_path=dict(),
    )

    module_kwargs = dict(
        required_if=[
            ('state', 'present', ('delay', 'health_monitor_timeout',
                                  'max_retries', 'pool',)),
        ],
        supports_check_mode=True,
    )

    def run(self):
        state = self.params['state']

        health_monitor = self._find()

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, health_monitor))

        if state == 'present' and not health_monitor:
            # Create health_monitor
            health_monitor = self._create()
            self.exit_json(
                changed=True,
                health_monitor=health_monitor.to_dict(computed=False))

        elif state == 'present' and health_monitor:
            # Update health_monitor
            update = self._build_update(health_monitor)
            if update:
                health_monitor = self._update(health_monitor, update)

            self.exit_json(
                changed=bool(update),
                health_monitor=health_monitor.to_dict(computed=False))

        elif state == 'absent' and health_monitor:
            # Delete health_monitor
            self._delete(health_monitor)
            self.exit_json(changed=True)

        elif state == 'absent' and not health_monitor:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, health_monitor):
        update = {}

        non_updateable_keys = [k for k in ['type']
                               if self.params[k] is not None
                               and self.params[k] != health_monitor[k]]

        pool_name_or_id = self.params['pool']
        pool = self.conn.load_balancer.find_pool(name_or_id=pool_name_or_id,
                                                 ignore_missing=False)
        # Field pool_id is not returned from self.conn.load_balancer.\
        # find_pool() so use pools instead.
        if health_monitor['pools'] != [dict(id=pool.id)]:
            non_updateable_keys.append('pool')

        if non_updateable_keys:
            self.fail_json(msg='Cannot update parameters {0}'
                               .format(non_updateable_keys))

        attributes = dict((k, self.params[k])
                          for k in ['delay', 'expected_codes', 'http_method',
                                    'is_admin_state_up', 'max_retries',
                                    'max_retries_down', 'type', 'url_path']
                          if self.params[k] is not None
                          and self.params[k] != health_monitor[k])

        health_monitor_timeout = self.params['health_monitor_timeout']
        if health_monitor_timeout is not None \
           and health_monitor_timeout != health_monitor['timeout']:
            attributes['timeout'] = health_monitor_timeout

        if attributes:
            update['attributes'] = attributes

        return update

    def _create(self):
        kwargs = dict((k, self.params[k])
                      for k in ['delay', 'expected_codes', 'http_method',
                                'is_admin_state_up', 'max_retries',
                                'max_retries_down', 'name', 'type', 'url_path']
                      if self.params[k] is not None)

        health_monitor_timeout = self.params['health_monitor_timeout']
        if health_monitor_timeout is not None:
            kwargs['timeout'] = health_monitor_timeout

        pool_name_or_id = self.params['pool']
        pool = self.conn.load_balancer.find_pool(name_or_id=pool_name_or_id,
                                                 ignore_missing=False)
        kwargs['pool_id'] = pool.id

        health_monitor = \
            self.conn.load_balancer.create_health_monitor(**kwargs)

        if self.params['wait']:
            health_monitor = self.sdk.resource.wait_for_status(
                self.conn.load_balancer, health_monitor,
                status='active',
                failures=['error'],
                wait=self.params['timeout'],
                attribute='provisioning_status')

        return health_monitor

    def _delete(self, health_monitor):
        self.conn.load_balancer.delete_health_monitor(health_monitor.id)

    def _find(self):
        name = self.params['name']
        return self.conn.load_balancer.find_health_monitor(name_or_id=name)

    def _update(self, health_monitor, update):
        attributes = update.get('attributes')
        if attributes:
            health_monitor = self.conn.load_balancer.update_health_monitor(
                health_monitor.id, **attributes)

        if self.params['wait']:
            health_monitor = self.sdk.resource.wait_for_status(
                self.conn.load_balancer, health_monitor,
                status='active',
                failures=['error'],
                wait=self.params['timeout'],
                attribute='provisioning_status')

        return health_monitor

    def _will_change(self, state, health_monitor):
        if state == 'present' and not health_monitor:
            return True
        elif state == 'present' and health_monitor:
            return bool(self._build_update(health_monitor))
        elif state == 'absent' and health_monitor:
            return True
        else:
            # state == 'absent' and not health_monitor:
            return False


def main():
    module = LoadBalancerHealthMonitorModule()
    module()


if __name__ == "__main__":
    main()
