#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# (c) 2021, Ashraf Hasson <ahasson@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: neutron_rbac_policy
short_description: Create or delete a Neutron RBAC policy.
author: OpenStack Ansible SIG
description:
  - Create, update or delete a policy to apply a RBAC rule against a network,
    security group or QoS Policy.
options:
  action:
    description:
      - Action for the RBAC policy.
      - Can be either of the following options C(access_as_shared) or
        C(access_as_external).
      - Cannot be changed when updating an existing policy.
      - Required when creating a RBAC policy rule, ignored when deleting a
        policy.
    choices: ['access_as_shared', 'access_as_external']
    type: str
  id:
    description:
      - The RBAC policy ID.
      - Required when deleting or updating an existing RBAC policy rule,
        ignored otherwise.
      - If a I(id) was provided but a policy with this ID cannot be found,
        an error will be raised.
    type: str
    aliases: ['policy_id']
  object_id:
    description:
      - The object ID (the subject of the policy) to which the RBAC rule
        applies.
      - Cannot be changed when updating an existing policy.
      - Required when creating a RBAC policy rule, ignored when deleting a
        policy.
    type: str
  object_type:
    description:
      - Type of the object that this RBAC policy affects.
      - Can be one of the following object types C(network), C(security_group)
        or C(qos_policy).
      - Cannot be changed when updating an existing policy.
      - Required when creating a RBAC policy rule, ignored when deleting a
        policy.
    choices: ['network', 'security_group', 'qos_policy']
    type: str
  project_id:
    description:
      - The ID of the project to which C(object_id) belongs to.
      - Cannot be changed when updating an existing policy.
      - Required when creating a RBAC policy rule, ignored when deleting a
        policy.
    type: str
  target_project_id:
    description:
      - The ID of the project to which access to be allowed or revoked aka
        disallowed.
      - Required when creating or updating a RBAC policy rule, ignored when
        deleting a policy.
    type: str
  target_all_project:
    description:
      - Whether all projects are targted for access.
      - If this option set to true, C(target_project_id) is ignored.
    type: bool
    default: 'false'
  state:
    description:
      - Whether the RBAC rule should be C(present) or C(absent).
    choices: ['present', 'absent']
    default: present
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Create or update RBAC policy
  neutron_rbac_policy:
    object_id: '7422172b-2961-475c-ac68-bd0f2a9960ad'
    object_type: 'network'
    project_id: '84b8774d595b41e89f3dfaa1fd76932d'
    target_project_id: 'a12f9ce1de0645e0a0b01c2e679f69ec'

- name: Delete RBAC policy
  openstack.cloud.openstack.neutron_rbac_policy:
    id: 'f625242a-6a73-47ac-8d1f-91440b2c617f'
    state: absent
'''

RETURN = r'''
rbac_policy:
  description: A dictionary describing the RBAC policy.
  returned: always
  type: dict
  contains:
    action:
      description:
        -  The access model specified by the RBAC rules
      type: str
      sample: "access_as_shared"
    id:
      description:
        - The ID of the RBAC rule/policy
      type: str
      sample: "4154ce0c-71a7-4d87-a905-09762098ddb9"
    name:
      description:
        - The name of the RBAC rule; usually null
      type: str
      sample: null
    object_id:
      description:
        - The UUID of the object to which the RBAC rules apply
      type: str
      sample: "7422172b-2961-475c-ac68-bd0f2a9960ad"
    object_type:
      description:
        - The object type to which the RBACs apply
      type: str
      sample: "network"
    project_id:
      description:
        - The UUID of the project to which access is granted
      type: str
      sample: "84b8774d595b41e89f3dfaa1fd76932c"
    target_project_id:
      description:
        - The UUID of the target project
      type: str
      sample: "c201a689c016435c8037977166f77368"
    tenant_id:
      description:
        - The UUID of the project to which access is granted. Deprecated.
      type: str
      sample: "84b8774d595b41e89f3dfaa1fd76932c"
policy:
    description: Same as C(rbac_policy), kept for backward compatibility.
    returned: always
    type: dict
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class NeutronRBACPolicy(OpenStackModule):
    all_project_symbol = '*'

    argument_spec = dict(
        action=dict(choices=['access_as_external', 'access_as_shared']),
        id=dict(aliases=['policy_id']),
        object_id=dict(),
        object_type=dict(choices=['security_group', 'qos_policy', 'network']),
        project_id=dict(),
        state=dict(default='present', choices=['absent', 'present']),
        target_project_id=dict(),
        target_all_project=dict(type='bool', default=False),
    )

    module_kwargs = dict(
        required_if=[
            ('state', 'present', ('target_project_id', 'target_all_project',), True),
            ('state', 'absent', ('id',)),
        ],
        supports_check_mode=True,
    )

    def run(self):
        target_all_project = self.params.get('target_all_project')
        if target_all_project:
            self.params['target_project_id'] = self.all_project_symbol

        state = self.params['state']

        policy = self._find()

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, policy))

        if state == 'present' and not policy:
            # Create policy
            policy = self._create()
            self.exit_json(changed=True,
                           rbac_policy=policy.to_dict(computed=False),
                           policy=policy.to_dict(computed=False))

        elif state == 'present' and policy:
            # Update policy
            update = self._build_update(policy)
            if update:
                policy = self._update(policy, update)

            self.exit_json(changed=bool(update),
                           rbac_policy=policy.to_dict(computed=False),
                           policy=policy.to_dict(computed=False))

        elif state == 'absent' and policy:
            # Delete policy
            self._delete(policy)
            self.exit_json(changed=True)

        elif state == 'absent' and not policy:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, policy):
        update = {}

        non_updateable_keys = [k for k in ['object_id', 'object_type',
                                           'project_id', 'action']
                               if self.params[k] is not None
                               and self.params[k] != policy[k]]

        if non_updateable_keys:
            self.fail_json(msg='Cannot update parameters {0}'
                               .format(non_updateable_keys))

        attributes = dict((k, self.params[k])
                          for k in ['target_project_id']
                          if self.params[k] is not None
                          and self.params[k] != policy[k])

        if attributes:
            update['attributes'] = attributes

        return update

    def _create(self):
        kwargs = dict((k, self.params[k])
                      for k in ['object_id', 'object_type',
                                'target_project_id', 'project_id',
                                'action']
                      if self.params[k] is not None)

        return self.conn.network.create_rbac_policy(**kwargs)

    def _delete(self, policy):
        self.conn.network.delete_rbac_policy(policy.id)

    def _find(self):
        id = self.params['id']

        if id is not None:
            return self.conn.network.find_rbac_policy(id)

        matches = self._find_matches()
        if len(matches) > 1:
            self.fail_json(msg='Found more a single matching RBAC policy'
                               ' which match the given parameters.')
        elif len(matches) == 1:
            return matches[0]
        else:  # len(matches) == 0
            return None

    def _find_matches(self):
        missing_keys = [k for k in ['action', 'object_id', 'object_type',
                                    'project_id', 'target_project_id']
                        if self.params[k] is None]
        if missing_keys:
            self.fail_json(msg='Missing parameter(s) for finding'
                               ' a matching RBAC policy: {0}'
                               .format(', '.join(missing_keys)))

        kwargs = dict((k, self.params[k])
                      for k in ['action', 'object_type', 'project_id'])

        policies = self.conn.network.rbac_policies(**kwargs)

        return [p for p in policies
                if any(p[k] == self.params[k]
                       for k in ['object_id'])]

    def _update(self, policy, update):
        attributes = update.get('attributes')
        if attributes:
            policy = self.conn.network.update_rbac_policy(policy.id,
                                                          **attributes)

        return policy

    def _will_change(self, state, policy):
        if state == 'present' and not policy:
            return True
        elif state == 'present' and policy:
            return bool(self._build_update(policy))
        elif state == 'absent' and policy:
            return True
        else:
            # state == 'absent' and not policy:
            return False


def main():
    module = NeutronRBACPolicy()
    module()


if __name__ == '__main__':
    main()
