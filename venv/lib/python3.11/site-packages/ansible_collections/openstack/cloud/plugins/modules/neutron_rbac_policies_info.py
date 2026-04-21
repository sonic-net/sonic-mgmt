#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# (c) 2021, Ashraf Hasson <ahasson@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: neutron_rbac_policies_info
short_description: Fetch Neutron RBAC policies.
author: OpenStack Ansible SIG
description:
  - Fetch RBAC policies against a network, security group or a QoS Policy for
    one or more projects.
options:
  action:
    description:
      - Action for the RBAC policy.
      - Can be either of the following options C(access_as_shared) or
        C(access_as_external).
      - Logically AND'ed with other filters.
    choices: ['access_as_shared', 'access_as_external']
    type: str
  object_id:
    description:
      - The object ID (the subject of the policy) to which the RBAC rules
        applies.
      - This is an ID of a network, security group or a qos policy.
      - Mutually exclusive with the C(object_type).
    type: str
  object_type:
    description:
      - Type of the object that this RBAC policy affects.
      - Can be one of the following object types C(network), C(security_group)
        or C(qos_policy).
      - Mutually exclusive with the C(object_id).
    choices: ['network', 'security_group', 'qos_policy']
    type: str
  policy_id:
    description:
      - The RBAC policy ID.
      - If C(policy_id) is not provided, all available policies will be
        fetched.
      - If C(policy_id) provided, all other filters are ignored.
    type: str
  project:
    description:
      - ID or name of the project to which C(object_id) belongs to.
      - Filters the RBAC rules based on the project name.
      - Logically AND'ed with other filters.
    type: str
    aliases: ['project_id']
  target_project_id:
    description:
      - The ID of the project this RBAC will be enforced.
      - Filters the RBAC rules based on the target project id.
      - Logically AND'ed with other filters.
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Get all rbac policies for a project
  openstack.cloud.neutron_rbac_policies_info:
    project: one_project
'''

RETURN = r'''
rbac_policies:
  description: List of Neutron RBAC policies.
  type: list
  elements: dict
  returned: always
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
policies:
    description: Same as C(rbac_policies), kept for backward compatibility.
    returned: always
    type: list
    elements: dict
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class NeutronRBACPoliciesInfo(OpenStackModule):
    argument_spec = dict(
        action=dict(choices=['access_as_external', 'access_as_shared']),
        object_id=dict(),
        object_type=dict(choices=['security_group', 'qos_policy', 'network']),
        policy_id=dict(),
        project=dict(aliases=['project_id']),
        target_project_id=dict(),
    )

    module_kwargs = dict(
        mutually_exclusive=[
            ('object_id', 'object_type'),
        ],
        supports_check_mode=True,
    )

    def run(self):
        project_name_or_id = self.params['project']
        project = None
        if project_name_or_id is not None:
            project = self.conn.identity.find_project(project_name_or_id)
            if not project:
                self.exit_json(changed=False, rbac_policies=[], policies=[])

        policy_id = self.params['policy_id']
        if policy_id:
            policy = self.conn.network.find_rbac_policy(policy_id)
            policies = [policy] if policy else []
        else:
            kwargs = dict((k, self.params[k])
                          for k in ['action', 'object_type']
                          if self.params[k] is not None)

            if project:
                kwargs['project_id'] = project.id

            policies = list(self.conn.network.rbac_policies(**kwargs))

        for k in ['object_id', 'target_project_id']:
            if self.params[k] is not None:
                policies = [p for p in policies if p[k] == self.params[k]]

        if project:
            policies = [p for p in policies
                        if p['location']['project']['id'] == project.id]

        policies = [p.to_dict(computed=False) for p in policies]
        self.exit_json(changed=False,
                       rbac_policies=policies,
                       policies=policies)


def main():
    module = NeutronRBACPoliciesInfo()
    module()


if __name__ == '__main__':
    main()
