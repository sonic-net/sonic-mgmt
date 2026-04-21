#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: identity_user
short_description: Manage a OpenStack identity (Keystone) user
author: OpenStack Ansible SIG
description:
  - Create, update or delete a OpenStack identity (Keystone) user.
options:
  default_project:
    description:
      - Name or ID of the project, the user should be created in.
    type: str
  description:
    description:
      - Description about the user.
    type: str
  domain:
    description:
      - Domain to create the user in if the cloud supports domains.
    type: str
  email:
    description:
      - Email address for the user.
    type: str
  is_enabled:
    description:
      - Whether the user is enabled or not.
    type: bool
    default: 'true'
    aliases: ['enabled']
  name:
    description:
      - Name of the user.
      - I(name) cannot be updated without deleting and re-creating the user.
    required: true
    type: str
  password:
    description:
      - Password for the user.
    type: str
  state:
    description:
      - Should the resource be present or absent.
    choices: [present, absent]
    default: present
    type: str
  update_password:
    choices: ['always', 'on_create']
    default: on_create
    description:
      - When I(update_password) is C(always), then the password will always be
        updated.
      - When I(update_password) is C(on_create), then the password is only set
        when creating a user.
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Create a user
  openstack.cloud.identity_user:
    cloud: mycloud
    state: present
    name: demouser
    password: secret
    email: demo@example.com
    domain: default
    default_project: demo

- name: Delete a user
  openstack.cloud.identity_user:
    cloud: mycloud
    state: absent
    name: demouser

- name: Create a user but don't update password if user exists
  openstack.cloud.identity_user:
    cloud: mycloud
    state: present
    name: demouser
    password: secret
    update_password: on_create
    email: demo@example.com
    domain: default
    default_project: demo

- name: Create a user without password
  openstack.cloud.identity_user:
    cloud: mycloud
    state: present
    name: demouser
    email: demo@example.com
    domain: default
    default_project: demo
'''

RETURN = r'''
user:
  description: Dictionary describing the identity user.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    default_project_id:
      description: User default project ID. Only present with Keystone >= v3.
      type: str
      sample: "4427115787be45f08f0ec22a03bfc735"
    description:
      description: The description of this user
      type: str
      sample: "a user"
    domain_id:
      description: User domain ID. Only present with Keystone >= v3.
      type: str
      sample: "default"
    email:
      description: User email address
      type: str
      sample: "demo@example.com"
    id:
      description: User ID
      type: str
      sample: "f59382db809c43139982ca4189404650"
    is_enabled:
      description: Indicates whether the user is enabled
      type: bool
    links:
      description: The links for the user resource
      type: dict
      elements: str
    name:
      description: Unique user name, within the owning domain
      type: str
      sample: "demouser"
    password:
      description: Credential used during authentication
      type: str
    password_expires_at:
      description: The date and time when the password expires. The time zone
                   is UTC. A none value means the password never expires
      type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule
from ansible_collections.openstack.cloud.plugins.module_utils.resource import StateMachine


class IdentityUserModule(OpenStackModule):
    argument_spec = dict(
        default_project=dict(),
        description=dict(),
        domain=dict(),
        email=dict(),
        is_enabled=dict(default=True, type='bool', aliases=['enabled']),
        name=dict(required=True),
        password=dict(no_log=True),
        state=dict(default='present', choices=['absent', 'present']),
        update_password=dict(default='on_create',
                             choices=['always', 'on_create']),
    )

    module_kwargs = dict()

    class _StateMachine(StateMachine):
        def _build_update(self, resource, attributes, updateable_attributes,
                          non_updateable_attributes,
                          update_password='on_create', **kwargs):
            if update_password == 'always' and 'password' not in attributes:
                self.ansible.fail_json(msg="update_password is 'always'"
                                           " but password is missing")
            elif update_password == 'on_create' and 'password' in attributes:
                attributes.pop('password')

            return super()._build_update(resource, attributes,
                                         updateable_attributes,
                                         non_updateable_attributes, **kwargs)

        def _find(self, attributes, **kwargs):
            query_args = dict((k, attributes[k])
                              for k in ['domain_id']
                              if k in attributes and attributes[k] is not None)

            return self.find_function(attributes['name'], **query_args)

    def run(self):
        sm = self._StateMachine(connection=self.conn,
                                service_name='identity',
                                type_name='user',
                                sdk=self.sdk,
                                ansible=self.ansible)

        kwargs = dict((k, self.params[k])
                      for k in ['state', 'timeout', 'update_password']
                      if self.params[k] is not None)

        kwargs['attributes'] = \
            dict((k, self.params[k])
                 for k in ['description', 'email', 'is_enabled', 'name',
                           'password']
                 if self.params[k] is not None)

        domain_name_or_id = self.params['domain']
        if domain_name_or_id is not None:
            domain = self.conn.identity.find_domain(domain_name_or_id,
                                                    ignore_missing=False)
            kwargs['attributes']['domain_id'] = domain.id

        default_project_name_or_id = self.params['default_project']
        if default_project_name_or_id is not None:
            query_args = dict((k, kwargs['attributes'][k])
                              for k in ['domain_id']
                              if k in kwargs['attributes']
                              and kwargs['attributes'][k] is not None)
            project = self.conn.identity.find_project(
                default_project_name_or_id, ignore_missing=False, **query_args)
            kwargs['attributes']['default_project_id'] = project.id

        user, is_changed = sm(check_mode=self.ansible.check_mode,
                              updateable_attributes=None,
                              non_updateable_attributes=['domain_id'],
                              wait=False,
                              **kwargs)

        if user is None:
            self.exit_json(changed=is_changed)
        else:
            self.exit_json(changed=is_changed,
                           user=user.to_dict(computed=False))


def main():
    module = IdentityUserModule()
    module()


if __name__ == '__main__':
    main()
