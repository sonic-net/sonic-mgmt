#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Damian Dabrowski <damian@dabrowski.cloud>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rabbitmq_feature_flag
short_description: Enables feature flag
description:
  - Allows to enable specified feature flag.
author: "Damian Dabrowski (@damiandabrowski5)"
version_added: '1.1.0'
options:
  name:
    description:
      - Feature flag name.
    type: str
    required: true
  node:
    description:
      - Erlang node name of the target rabbit node.
    type: str
    default: rabbit
'''

EXAMPLES = r'''
- name: Enable the 'maintenance_mode_status' feature flag on 'rabbit@node-1'
  community.rabbitmq.rabbitmq_feature_flag:
    name: maintenance_mode_status
    node: rabbit@node-1
'''

from ansible.module_utils.basic import AnsibleModule


class RabbitMqFeatureFlag(object):

    def __init__(self, module, name, node):
        self.module = module
        self.name = name
        self.node = node
        self._rabbitmqctl = module.get_bin_path('rabbitmqctl', True)
        self.state = self.get_flag_state()

    def _exec(self, args, force_exec_in_check_mode=False):
        if not self.module.check_mode or (self.module.check_mode and force_exec_in_check_mode):
            cmd = [self._rabbitmqctl, '-q', '-n', self.node]
            rc, out, err = self.module.run_command(cmd + args, check_rc=True)
            return out.splitlines()
        return list()

    def get_flag_state(self):
        global_parameters = self._exec(['list_feature_flags'], True)

        for param_item in global_parameters:
            name, state = param_item.split('\t')
            if name == self.name:
                if state == 'enabled':
                    return 'enabled'
                return 'disabled'
        return 'unavailable'

    def enable(self):
        self._exec(['enable_feature_flag', self.name])


def main():
    arg_spec = dict(
        name=dict(type='str', required=True),
        node=dict(type='str', default='rabbit')
    )
    module = AnsibleModule(
        argument_spec=arg_spec,
        supports_check_mode=True
    )

    name = module.params['name']
    node = module.params['node']

    result = dict(changed=False)
    rabbitmq_feature_flag = RabbitMqFeatureFlag(module, name, node)

    if rabbitmq_feature_flag.state == 'disabled':
        rabbitmq_feature_flag.enable()
        result['changed'] = True
    if rabbitmq_feature_flag.state == 'unavailable':
        module.fail_json(msg="%s feature flag is not available" % (name))

    module.exit_json(**result)


if __name__ == '__main__':
    main()
