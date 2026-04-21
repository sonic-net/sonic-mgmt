#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 IBM
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: identity_role
short_description: Manage a OpenStack identity (Keystone) role
author: OpenStack Ansible SIG
description:
  - Create, update or delete a OpenStack identity (Keystone) role.
options:
  description:
    description:
      - Role description.
    type: str
  domain_id:
    description:
      - Domain id to create the role in.
    type: str
  name:
    description:
      - Role name.
    required: true
    type: str
  state:
    description:
      - Should the resource be present or absent.
    choices: ['present', 'absent']
    default: present
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Create a role named demo
  openstack.cloud.identity_role:
    cloud: mycloud
    state: present
    name: demo

- name: Delete the role named demo
  openstack.cloud.identity_role:
    cloud: mycloud
    state: absent
    name: demo
'''

RETURN = r'''
role:
  description: Dictionary describing the identity role.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    description:
      description: Description of the role resource
      type: str
      sample: role description
    domain_id:
      description: Domain to which the role belongs
      type: str
      sample: default
    id:
      description: Unique role ID.
      type: str
      sample: "677bfab34c844a01b88a217aa12ec4c2"
    links:
      description: Links for the role resource
      type: list
    name:
      description: Role name.
      type: str
      sample: "demo"
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule
from ansible_collections.openstack.cloud.plugins.module_utils.resource import StateMachine


class IdentityRoleModule(OpenStackModule):
    argument_spec = dict(
        description=dict(),
        domain_id=dict(),
        name=dict(required=True),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    class _StateMachine(StateMachine):
        def _find(self, attributes, **kwargs):
            kwargs = dict((k, attributes[k])
                          for k in ['domain_id']
                          if k in attributes and attributes[k] is not None)

            return self.find_function(attributes['name'], **kwargs)

    def run(self):
        sm = self._StateMachine(connection=self.conn,
                                service_name='identity',
                                type_name='role',
                                sdk=self.sdk)

        kwargs = dict((k, self.params[k])
                      for k in ['state', 'timeout']
                      if self.params[k] is not None)

        kwargs['attributes'] = \
            dict((k, self.params[k])
                 for k in ['description', 'domain_id', 'name']
                 if self.params[k] is not None)

        role, is_changed = sm(check_mode=self.ansible.check_mode,
                              updateable_attributes=None,
                              non_updateable_attributes=['domain_id'],
                              wait=False,
                              **kwargs)

        if role is None:
            self.exit_json(changed=is_changed)
        else:
            self.exit_json(changed=is_changed,
                           role=role.to_dict(computed=False))


def main():
    module = IdentityRoleModule()
    module()


if __name__ == '__main__':
    main()
