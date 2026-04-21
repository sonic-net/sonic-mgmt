#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Damian Dabrowski <damian@dabrowski.cloud>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rabbitmq_upgrade
short_description: Execute rabbitmq-upgrade commands
description:
  - Allows to execute rabbitmq-upgrade commands
author: "Damian Dabrowski (@damiandabrowski5)"
version_added: '1.1.0'
options:
  action:
    description:
      - Specify action to be executed.
    type: str
    required: true
    choices: ['await_online_quorum_plus_one','await_online_synchronized_mirror','post_upgrade','drain','revive']
  node:
    description:
      - Erlang node name of the target rabbit node.
    type: str
    required: false
    default: rabbit
'''

EXAMPLES = r'''
- name: Drain 'rabbit@node-1' node (in other words, put it into maintenance mode)
  community.rabbitmq.rabbitmq_upgrade:
    action: drain
    node: rabbit@node-1
'''

import json
from ansible.module_utils.basic import AnsibleModule


class RabbitMqUpgrade(object):

    def __init__(self, module, action, node, result):
        self.module = module
        self.action = action
        self.node = node
        self.result = result

    def _exec(self, binary, args, force_exec_in_check_mode=False):
        if not self.module.check_mode or (self.module.check_mode and force_exec_in_check_mode):
            cmd = [self.module.get_bin_path(binary, True)]
            rc, out, err = self.module.run_command(cmd + args, check_rc=True)
            return out.splitlines()
        return list()

    def is_node_under_maintenance(self):
        cmd = self._exec('rabbitmq-diagnostics',
                         ['--formatter', 'json', 'status', '-n', self.node], True)
        node_status = json.loads("".join(cmd))
        maint_enabled = node_status['is_under_maintenance']
        if maint_enabled:
            return True
        return False

    def is_maint_flag_enabled(self):
        feature_flags = self._exec('rabbitmqctl', ['list_feature_flags', '-q'], True)
        for param_item in feature_flags:
            name, state = param_item.split('\t')
            if name == 'maintenance_mode_status' and state == 'enabled':
                return True
        return False

    def drain(self):
        if not self.is_maint_flag_enabled():
            self.module.fail_json(msg='maintenance_mode_status feature_flag is disabled.')
        if not self.is_node_under_maintenance():
            self._exec('rabbitmq-upgrade', ['drain', '-n', self.node])
            self.result['changed'] = True

    def revive(self):
        if not self.is_maint_flag_enabled():
            self.module.fail_json(msg='maintenance_mode_status feature_flag is disabled.')
        if self.is_node_under_maintenance():
            self._exec('rabbitmq-upgrade', ['revive', '-n', self.node])
            self.result['changed'] = True

    def await_online_quorum_plus_one(self):
        self._exec('rabbitmq-upgrade', ['await_online_quorum_plus_one'])
        self.result['changed'] = True

    def await_online_synchronized_mirror(self):
        self._exec('rabbitmq-upgrade', ['await_online_synchronized_mirror'])
        self.result['changed'] = True

    def post_upgrade(self):
        self._exec('rabbitmq-upgrade', ['post_upgrade'])
        self.result['changed'] = True


def main():
    arg_spec = dict(
        action=dict(
            choices=['await_online_quorum_plus_one', 'await_online_synchronized_mirror', 'post_upgrade', 'drain', 'revive'],
            required=True),
        node=dict(type='str', default='rabbit')
    )
    module = AnsibleModule(
        argument_spec=arg_spec,
        supports_check_mode=True
    )

    action = module.params['action']
    node = module.params['node']
    result = dict(changed=False)

    rabbitmq_upgrade = RabbitMqUpgrade(module, action, node, result)

    getattr(rabbitmq_upgrade, action)()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
