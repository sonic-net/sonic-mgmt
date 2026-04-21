#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 IBM
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: identity_group
short_description: Manage a OpenStack identity (Keystone) group
author: OpenStack Ansible SIG
description:
  - Create, update or delete an OpenStack identity (Keystone) group.
options:
  description:
    description:
      - Group description.
    type: str
  domain_id:
    description:
      - Domain id to create the group in.
    type: str
  name:
    description:
      - Group name
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
- name: Create a group named "demo"
  openstack.cloud.identity_group:
    cloud: mycloud
    state: present
    name: demo
    description: "Demo Group"
    domain_id: demoid

- name: Update the description on existing demo group
  openstack.cloud.identity_group:
    cloud: mycloud
    state: present
    name: demo
    description: "Something else"
    domain_id: demoid

- name: Delete group named demo
  openstack.cloud.identity_group:
    cloud: mycloud
    state: absent
    name: demo
'''

RETURN = r'''
group:
  description: Dictionary describing the identity group.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    description:
      description: Group description
      type: str
      sample: "Demo Group"
    domain_id:
      description: Domain for the group
      type: str
      sample: "default"
    id:
      description: Unique group ID
      type: str
      sample: "ee6156ff04c645f481a6738311aea0b0"
    name:
      description: Group name
      type: str
      sample: "demo"
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule
from ansible_collections.openstack.cloud.plugins.module_utils.resource import StateMachine


class IdentityGroupModule(OpenStackModule):
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
                                type_name='group',
                                sdk=self.sdk)

        kwargs = dict((k, self.params[k])
                      for k in ['state', 'timeout']
                      if self.params[k] is not None)

        kwargs['attributes'] = \
            dict((k, self.params[k])
                 for k in ['description', 'domain_id', 'name']
                 if self.params[k] is not None)

        group, is_changed = sm(check_mode=self.ansible.check_mode,
                               updateable_attributes=None,
                               non_updateable_attributes=['domain_id'],
                               wait=False,
                               **kwargs)

        if group is None:
            self.exit_json(changed=is_changed)
        else:
            self.exit_json(changed=is_changed,
                           group=group.to_dict(computed=False))


def main():
    module = IdentityGroupModule()
    module()


if __name__ == '__main__':
    main()
