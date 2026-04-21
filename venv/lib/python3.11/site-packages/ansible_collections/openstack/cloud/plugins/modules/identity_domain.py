#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: identity_domain
short_description: Manage OpenStack identity (Keystone) domains
author: OpenStack Ansible SIG
description:
  - Create, update or delete OpenStack identity (Keystone) domains.
options:
  description:
    description:
      - Domain description.
    type: str
  is_enabled:
    description:
      - Whether this domain is enabled or not.
    type: bool
    aliases: ['enabled']
  name:
    description:
      - Domain name.
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
- name: Create a domain
  openstack.cloud.identity_domain:
    cloud: mycloud
    state: present
    name: demo
    description: Demo Domain

- name: Delete a domain
  openstack.cloud.identity_domain:
    cloud: mycloud
    state: absent
    name: demo
'''

RETURN = r'''
domain:
  description: Dictionary describing the domain.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    description:
      description: Domain description.
      type: str
      sample: "Demo Domain"
    id:
      description: Domain ID.
      type: str
      sample: "474acfe5-be34-494c-b339-50f06aa143e4"
    is_enabled:
      description: Domain description.
      type: bool
      sample: True
    links:
      description: The links related to the domain resource
      type: list
    name:
      description: Domain name.
      type: str
      sample: "demo"
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule
from ansible_collections.openstack.cloud.plugins.module_utils.resource import StateMachine


class IdentityDomainModule(OpenStackModule):
    argument_spec = dict(
        description=dict(),
        is_enabled=dict(type='bool', aliases=['enabled']),
        name=dict(required=True),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    class _StateMachine(StateMachine):
        def _delete(self, resource, attributes, timeout, wait, **kwargs):
            # a domain must be disabled before it can be deleted and
            # openstacksdk's cloud layer delete_domain() will just do that.
            self.connection.delete_domain(resource['id'])

    def run(self):
        sm = self._StateMachine(connection=self.conn,
                                service_name='identity',
                                type_name='domain',
                                sdk=self.sdk)

        kwargs = dict((k, self.params[k])
                      for k in ['state', 'timeout']
                      if self.params[k] is not None)

        kwargs['attributes'] = \
            dict((k, self.params[k])
                 for k in ['description', 'is_enabled', 'name']
                 if self.params[k] is not None)

        domain, is_changed = sm(check_mode=self.ansible.check_mode,
                                updateable_attributes=None,
                                non_updateable_attributes=None,
                                wait=False,
                                **kwargs)

        if domain is None:
            self.exit_json(changed=is_changed)
        else:
            self.exit_json(changed=is_changed,
                           domain=domain.to_dict(computed=False))


def main():
    module = IdentityDomainModule()
    module()


if __name__ == '__main__':
    main()
