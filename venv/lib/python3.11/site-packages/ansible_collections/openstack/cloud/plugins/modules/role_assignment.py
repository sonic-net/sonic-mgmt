#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 IBM
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: role_assignment
short_description: Assign OpenStack identity groups and users to roles
author: OpenStack Ansible SIG
description:
  - Grant and revoke roles in either project or domain context for
    OpenStack identity (Keystone) users and groups.
options:
  domain:
    description:
      - Name or ID of the domain to scope the role association to.
      - Valid only with keystone version 3.
      - Required if I(project) is not specified.
      - When I(project) is specified, then I(domain) will not be used for
        scoping the role association, only for finding resources. Deprecated
        for finding resources, please use I(group_domain), I(project_domain),
        I(role_domain), or I(user_domain).
      - "When scoping the role association, I(project) has precedence over
         I(domain) and I(domain) has precedence over I(system): When I(project)
         is specified, then I(domain) and I(system) are not used for role
         association. When I(domain) is specified, then I(system) will not be
         used for role association."
    type: str
  group:
    description:
      - Name or ID for the group.
      - Valid only with keystone version 3.
      - If I(group) is not specified, then I(user) is required. Both may not be
        specified at the same time.
      - You can supply I(group_domain) or the deprecated usage of I(domain) to
        find group resources.
    type: str
  group_domain:
    description:
      - Name or ID for the domain.
      - Valid only with keystone version 3.
      - Only valid for finding group resources.
    type: str
  project:
    description:
      - Name or ID of the project to scope the role association to.
      - If you are using keystone version 2, then this value is required.
      - When I(project) is specified, then I(domain) will not be used for
        scoping the role association, only for finding resources. Prefer
        I(group_domain) over I(domain).
      - "When scoping the role association, I(project) has precedence over
         I(domain) and I(domain) has precedence over I(system): When I(project)
         is specified, then I(domain) and I(system) are not used for role
         association. When I(domain) is specified, then I(system) will not be
         used for role association."
    type: str
  project_domain:
    description:
      - Name or ID for the domain.
      - Valid only with keystone version 3.
      - Only valid for finding project resources.
    type: str
  role:
    description:
      - Name or ID for the role.
    required: true
    type: str
  role_domain:
    description:
      - Name or ID for the domain.
      - Valid only with keystone version 3.
      - Only valid for finding role resources.
    type: str
  state:
    description:
      - Should the roles be present or absent on the user.
    choices: [present, absent]
    default: present
    type: str
  system:
    description:
      - Name of system to scope the role association to.
      - Valid only with keystone version 3.
      - Required if I(project) and I(domain) are not specified.
      - "When scoping the role association, I(project) has precedence over
         I(domain) and I(domain) has precedence over I(system): When I(project)
         is specified, then I(domain) and I(system) are not used for role
         association. When I(domain) is specified, then I(system) will not be
         used for role association."
    type: str
  user:
    description:
      - Name or ID for the user.
      - If I(user) is not specified, then I(group) is required. Both may not be
        specified at the same time.
    type: str
  user_domain:
    description:
      - Name or ID for the domain.
      - Valid only with keystone version 3.
      - Only valid for finding user resources.
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Grant an admin role on the user admin in the project project1
  openstack.cloud.role_assignment:
    cloud: mycloud
    user: admin
    role: admin
    project: project1

- name: Revoke the admin role from the user barney in the newyork domain
  openstack.cloud.role_assignment:
    cloud: mycloud
    state: absent
    user: barney
    role: admin
    domain: newyork
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class IdentityRoleAssignmentModule(OpenStackModule):
    argument_spec = dict(
        domain=dict(),
        group=dict(),
        group_domain=dict(type='str'),
        project=dict(),
        project_domain=dict(type='str'),
        role=dict(required=True),
        role_domain=dict(type='str'),
        state=dict(default='present', choices=['absent', 'present']),
        system=dict(),
        user=dict(),
        user_domain=dict(type='str'),
    )

    module_kwargs = dict(
        required_one_of=[
            ('user', 'group'),
            ('domain', 'project', 'system'),
        ],
        mutually_exclusive=[
            ('user', 'group'),
            ('project', 'system'),  # domain should be part of this
        ],
        supports_check_mode=True
    )

    def _find_domain_id(self, domain):
        if domain is not None:
            domain = self.conn.identity.find_domain(domain,
                                                    ignore_missing=False)
            return dict(domain_id=domain['id'])
        return dict()

    def run(self):
        filters = {}
        group_find_filters = {}
        project_find_filters = {}
        role_find_filters = {}
        user_find_filters = {}

        role_find_filters.update(self._find_domain_id(
            self.params['role_domain']))
        role_name_or_id = self.params['role']
        role = self.conn.identity.find_role(role_name_or_id,
                                            ignore_missing=False,
                                            **role_find_filters)
        filters['role_id'] = role['id']

        domain_name_or_id = self.params['domain']
        if domain_name_or_id is not None:
            domain = self.conn.identity.find_domain(
                domain_name_or_id, ignore_missing=False)
            filters['scope_domain_id'] = domain['id']
            group_find_filters['domain_id'] = domain['id']
            project_find_filters['domain_id'] = domain['id']
            user_find_filters['domain_id'] = domain['id']

        user_name_or_id = self.params['user']
        if user_name_or_id is not None:
            user_find_filters.update(self._find_domain_id(
                self.params['user_domain']))
            user = self.conn.identity.find_user(
                user_name_or_id, ignore_missing=False,
                **user_find_filters)
            filters['user_id'] = user['id']
        else:
            user = None

        group_name_or_id = self.params['group']
        if group_name_or_id is not None:
            group_find_filters.update(self._find_domain_id(
                self.params['group_domain']))
            group = self.conn.identity.find_group(
                group_name_or_id, ignore_missing=False,
                **group_find_filters)
            filters['group_id'] = group['id']
        else:
            group = None

        system_name = self.params['system']
        if system_name is not None:
            # domain has precedence over system
            if 'scope_domain_id' not in filters:
                filters['scope.system'] = system_name

        project_name_or_id = self.params['project']
        if project_name_or_id is not None:
            project_find_filters.update(self._find_domain_id(
                self.params['project_domain']))
            project = self.conn.identity.find_project(
                project_name_or_id, ignore_missing=False,
                **project_find_filters)
            filters['scope_project_id'] = project['id']

            # project has precedence over domain and system
            filters.pop('scope_domain_id', None)
            filters.pop('scope.system', None)

        role_assignments = list(self.conn.identity.role_assignments(**filters))

        state = self.params['state']
        if self.ansible.check_mode:
            self.exit_json(
                changed=((state == 'present' and not role_assignments)
                         or (state == 'absent' and role_assignments)))

        if state == 'present' and not role_assignments:
            if 'scope_domain_id' in filters:
                if user is not None:
                    self.conn.identity.assign_domain_role_to_user(
                        filters['scope_domain_id'], user, role)
                else:
                    self.conn.identity.assign_domain_role_to_group(
                        filters['scope_domain_id'], group, role)
            elif 'scope_project_id' in filters:
                if user is not None:
                    self.conn.identity.assign_project_role_to_user(
                        filters['scope_project_id'], user, role)
                else:
                    self.conn.identity.assign_project_role_to_group(
                        filters['scope_project_id'], group, role)
            elif 'scope.system' in filters:
                if user is not None:
                    self.conn.identity.assign_system_role_to_user(
                        user, role, filters['scope.system'])
                else:
                    self.conn.identity.assign_system_role_to_group(
                        group, role, filters['scope.system'])
            self.exit_json(changed=True)
        elif state == 'absent' and role_assignments:
            if 'scope_domain_id' in filters:
                if user is not None:
                    self.conn.identity.unassign_domain_role_from_user(
                        filters['scope_domain_id'], user, role)
                else:
                    self.conn.identity.unassign_domain_role_from_group(
                        filters['scope_domain_id'], group, role)
            elif 'scope_project_id' in filters:
                if user is not None:
                    self.conn.identity.unassign_project_role_from_user(
                        filters['scope_project_id'], user, role)
                else:
                    self.conn.identity.unassign_project_role_from_group(
                        filters['scope_project_id'], group, role)
            elif 'scope.system' in filters:
                if user is not None:
                    self.conn.identity.unassign_system_role_from_user(
                        user, role, filters['scope.system'])
                else:
                    self.conn.identity.unassign_system_role_from_group(
                        group, role, filters['scope.system'])
            self.exit_json(changed=True)
        else:
            self.exit_json(changed=False)


def main():
    module = IdentityRoleAssignmentModule()
    module()


if __name__ == '__main__':
    main()
