#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 Catalyst IT Limited
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: server_group
short_description: Manage OpenStack server groups
author: OpenStack Ansible SIG
description:
   - Add or remove server groups from OpenStack.
options:
   state:
     description:
        - Indicate desired state of the resource. When I(state) is C(present),
          then I(policy) is required.
     choices: ['present', 'absent']
     default: present
     type: str
   name:
     description:
        - Server group name.
     required: true
     type: str
   policy:
     description:
        - Represents the current name of the policy.
     choices: ['anti-affinity', 'affinity', 'soft-anti-affinity', 'soft-affinity']
     type: str
   rules:
     description:
        - Rules to be applied to the policy. Currently, only the
          C(max_server_per_host) rule is supported for the C(anti-affinity)
          policy.
     type: dict
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
- name: Create a server group with 'affinity' policy.
  openstack.cloud.server_group:
    cloud: "{{ cloud }}"
    state: present
    name: my_server_group
    policy: affinity

- name: Delete 'my_server_group' server group.
  openstack.cloud.server_group:
    cloud: "{{ cloud }}"
    state: absent
    name: my_server_group
'''

RETURN = '''
server_group:
    description: Object representing the server group
    returned: On success when I(state) is present
    type: dict
    contains:
        id:
            description: Unique UUID.
            returned: always
            type: str
        name:
            description: The name of the server group.
            returned: always
            type: str
        policies:
            description: |
                A list of exactly one policy name to associate with the group.
                Available until microversion 2.63
            returned: always
            type: list
        policy:
            description: |
                Represents the name of the policy. Available from version 2.64 on.
            returned: always
            type: str
        member_ids:
            description: The list of members in the server group
            returned: always
            type: list
        metadata:
            description: Metadata key and value pairs.
            returned: always
            type: dict
        project_id:
            description: The project ID who owns the server group.
            returned: always
            type: str
        rules:
            description: |
                The rules field, applied to the policy. Currently, only the
                C(max_server_per_host) rule is supported for the
                C(anti-affinity) policy.
            returned: always
            type: dict
        user_id:
            description: The user ID who owns the server group.
            returned: always
            type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class ServerGroupModule(OpenStackModule):
    argument_spec = dict(
        name=dict(required=True),
        policy=dict(choices=['anti-affinity', 'affinity', 'soft-anti-affinity',
                             'soft-affinity']),
        state=dict(default='present', choices=['absent', 'present']),
        rules=dict(type='dict')
    )

    module_kwargs = dict(
        supports_check_mode=True,
        required_if=[
            ('state', 'present', ['policy'])
        ],
    )

    def _system_state_change(self, state, server_group):
        if state == 'present' and not server_group:
            return True
        if state == 'absent' and server_group:
            return True

        return False

    def run(self):
        name = self.params['name']
        state = self.params['state']

        server_group = self.conn.compute.find_server_group(name)

        if self.ansible.check_mode:
            self.exit_json(
                changed=self._system_state_change(state, server_group)
            )

        changed = False
        if state == 'present':
            if not server_group:
                kwargs = {k: self.params[k]
                          for k in ['name', 'policy', 'rules']
                          if self.params[k] is not None}
                server_group = self.conn.compute.create_server_group(**kwargs)
                changed = True

            self.exit_json(
                changed=changed,
                server_group=server_group.to_dict(computed=False)
            )
        if state == 'absent':
            if server_group:
                self.conn.compute.delete_server_group(server_group)
                changed = True
            self.exit_json(changed=changed)


def main():
    module = ServerGroupModule()
    module()


if __name__ == '__main__':
    main()
