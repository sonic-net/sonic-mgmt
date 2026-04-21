#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020, Sagi Shnaidman <sshnaidm@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: identity_role_info
short_description: Fetch OpenStack identity (Keystone) roles
author: OpenStack Ansible SIG
description:
  - Fetch OpenStack identity (Keystone) roles.
options:
  domain_id:
    description:
      - Domain ID which owns the role.
    type: str
    required: false
  name:
    description:
      - Name or ID of the role.
    type: str
    required: false
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
roles:
  description: List of dictionaries describing matching identity roles.
  returned: always
  type: list
  elements: dict
  contains:
    description:
      description: User-facing description of the role.
      type: str
    domain_id:
      description: References the domain ID which owns the role.
      type: str
    id:
      description: Unique ID for the role
      type: str
    links:
      description: The links for the service resources
      type: dict
    name:
      description: Unique role name, within the owning domain.
      type: str
'''

EXAMPLES = r'''
- name: Retrieve info about all roles
  openstack.cloud.identity_role_info:
    cloud: mycloud

- name: Retrieve info about all roles in specific domain
  openstack.cloud.identity_role_info:
    cloud: mycloud
    domain_id: some_domain_id

- name: Retrieve info about role 'admin'
  openstack.cloud.identity_role_info:
    cloud: mycloud
    name: admin
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class IdentityRoleInfoModule(OpenStackModule):
    argument_spec = dict(
        domain_id=dict(),
        name=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True,
    )

    def run(self):
        kwargs = dict((k, self.params[k])
                      for k in ['domain_id']
                      if self.params[k] is not None)

        name_or_id = self.params['name']
        if name_or_id is not None:
            kwargs['name_or_id'] = name_or_id

        self.exit_json(changed=False,
                       roles=[r.to_dict(computed=False)
                              for r in self.conn.search_roles(**kwargs)])


def main():
    module = IdentityRoleInfoModule()
    module()


if __name__ == '__main__':
    main()
