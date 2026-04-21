#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015, Jesse Keating <jlk@derpops.bike>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: server_action
short_description: Perform actions on OpenStack compute (Nova) instances
author: OpenStack Ansible SIG
description:
  - Perform actions on OpenStack compute (Nova) instances aka servers.
options:
  action:
    description:
      - Action to perform.
      - By default, only server owners and administrators are allowed to
        perform actions C(pause), C(unpause), C(suspend), C(resume), C(lock),
        C(unlock) and C(shelve_offload).
    choices: [lock, pause, reboot_hard, reboot_soft, rebuild, resume, shelve,
              shelve_offload, start, stop, suspend, unlock, unpause, unshelve]
    type: str
    required: true
  admin_password:
    description:
      - Admin password for server to rebuild.
    type: str
  all_projects:
    description:
      - Whether to search for server in all projects or the current project
        only.
    type: bool
    default: false
  image:
    description:
      - Image name or ID the server should be rebuilt with.
    type: str
  name:
    description:
      - Server name or ID.
    required: true
    type: str
    aliases: ['server']
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Pauses a compute instance
  openstack.cloud.server_action:
    cloud: devstack-admin
    action: pause
    server: vm1
    timeout: 200
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class ServerActionModule(OpenStackModule):
    argument_spec = dict(
        action=dict(required=True,
                    choices=['stop', 'start', 'pause', 'unpause',
                             'lock', 'unlock', 'suspend', 'reboot_soft',
                             'reboot_hard', 'resume', 'rebuild', 'shelve',
                             'shelve_offload', 'unshelve']),
        admin_password=dict(no_log=True),
        all_projects=dict(type='bool', default=False),
        image=dict(),
        name=dict(required=True, aliases=['server']),
    )

    module_kwargs = dict(
        required_if=[('action', 'rebuild', ['image'])],
        supports_check_mode=True,
    )

    # If I(action) is set to C(shelve) then according to OpenStack's Compute
    # API, the shelved server is in one of two possible states:
    #
    #  SHELVED:           The server is in shelved state. Depends on the shelve
    #                     offload time, the server will be automatically
    #                     shelved offloaded.
    #  SHELVED_OFFLOADED: The shelved server is offloaded (removed from the
    #                     compute host) and it needs unshelved action to be
    #                     used again.
    #
    # But wait_for_server can only wait for a single server state. If a shelved
    # server is offloaded immediately, then a exceptions.ResourceTimeout will
    # be raised if I(action) is set to C(shelve). This is likely to happen
    # because shelved_offload_time in Nova's config is set to 0 by default.
    # This also applies if you boot the server from volumes.
    #
    # Calling C(shelve_offload) instead of C(shelve) will also fail most likely
    # because the default policy does not allow C(shelve_offload) for non-admin
    # users while C(shelve) is allowed for admin users and server owners.
    #
    # As we cannot retrieve shelved_offload_time from Nova's config, we fall
    # back to waiting for one state and if that fails then we fetch the
    # server's state and match it against the other valid states from
    # _action_map.
    #
    # Ref.: https://docs.openstack.org/api-guide/compute/server_concepts.html

    _action_map = {'stop': ['SHUTOFF'],
                   'start': ['ACTIVE'],
                   'pause': ['PAUSED'],
                   'unpause': ['ACTIVE'],
                   'lock': ['ACTIVE'],
                   'unlock': ['ACTIVE'],
                   'suspend': ['SUSPENDED'],
                   'reboot_soft': ['ACTIVE'],
                   'reboot_hard': ['ACTIVE'],
                   'resume': ['ACTIVE'],
                   'rebuild': ['ACTIVE'],
                   'shelve': ['SHELVED_OFFLOADED', 'SHELVED'],
                   'shelve_offload': ['SHELVED_OFFLOADED'],
                   'unshelve': ['ACTIVE']}

    def run(self):
        # TODO: Replace with self.conn.compute.find_server(
        #       self.params['name'], all_projects=self.params['all_projects'],
        #       ignore_missing=False) when [0] has been merged.
        # [0] https://review.opendev.org/c/openstack/openstacksdk/+/857936/
        server = self.conn.get_server(
            name_or_id=self.params['name'],
            detailed=True,
            all_projects=self.params['all_projects'])
        if not server:
            self.fail_json(msg='No Server found for {0}'
                               .format(self.params['name']))

        action = self.params['action']

        # rebuild does not depend on state
        will_change = (
            (action == 'rebuild')
            # `reboot_*` actions do not change state, servers remain `ACTIVE`
            or (action == 'reboot_hard')
            or (action == 'reboot_soft')
            or (action == 'lock' and not server['is_locked'])
            or (action == 'unlock' and server['is_locked'])
            or server.status.lower() not in [a.lower()
                                             for a
                                             in self._action_map[action]])

        if not will_change:
            self.exit_json(changed=False)
        elif self.ansible.check_mode:
            self.exit_json(changed=True)
        # else perform action

        if action == 'rebuild':
            # rebuild should ensure images exists
            image = self.conn.image.find_image(self.params['image'],
                                               ignore_missing=False)
            kwargs = dict(server=server,
                          name=server['name'],
                          image=image['id'])

            admin_password = self.params['admin_password']
            if admin_password is not None:
                kwargs['admin_password'] = admin_password

            self.conn.compute.rebuild_server(**kwargs)
        elif action == 'shelve_offload':
            # TODO: Replace with shelve_offload function call when [0] has been
            #       merged.
            # [0] https://review.opendev.org/c/openstack/openstacksdk/+/857947

            # shelve_offload is not supported in openstacksdk <= 1.0.0
            response = self.conn.compute.post(
                '/servers/{server_id}/action'.format(server_id=server['id']),
                json={'shelveOffload': None})
            self.sdk.exceptions.raise_from_response(response)
        else:  # action != 'rebuild' and action != 'shelve_offload'
            action_name = action + "_server"

            # reboot_* actions are using reboot_server method with an
            # additional argument
            if action in ['reboot_soft', 'reboot_hard']:
                action_name = 'reboot_server'

            func_name = getattr(self.conn.compute, action_name)

            # Do the action
            if action == 'reboot_soft':
                func_name(server, 'SOFT')
            elif action == 'reboot_hard':
                func_name(server, 'HARD')
            else:
                func_name(server)

        if self.params['wait']:
            for count in self.sdk.utils.iterate_timeout(
                timeout=self.params['timeout'],
                message='Timeout waiting for action {0} to be completed.'
                        .format(action)
            ):
                server = self.conn.compute.get_server(server['id'])

                if (action == 'lock' and server['is_locked']) \
                   or (action == 'unlock' and not server['is_locked']):
                    break

                states = [s.lower() for s in self._action_map[action]]
                if server.status.lower() in states:
                    break

        self.exit_json(changed=True)


def main():
    module = ServerActionModule()
    module()


if __name__ == '__main__':
    main()
