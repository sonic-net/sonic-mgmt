#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 Hewlett-Packard Enterprise Corporation
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: identity_user_info
short_description: Fetch OpenStack identity (Keystone) users
author: OpenStack Ansible SIG
description:
  - Fetch OpenStack identity (Keystone) users.
options:
  domain:
    description:
      - Name or ID of the domain containing the user.
    type: str
  filters:
    description:
      - A dictionary of meta data to use for further filtering. Elements of
        this dictionary may be additional dictionaries.
    type: dict
  name:
    description:
      - Name or ID of the user.
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Gather previously created users
  openstack.cloud.identity_user_info:
    cloud: awesomecloud

- name: Gather previously created user by name
  openstack.cloud.identity_user_info:
    cloud: awesomecloud
    name: demouser

- name: Gather previously created user in a specific domain
  openstack.cloud.identity_user_info:
    cloud: awesomecloud
    name: demouser
    domain: admindomain

- name: Gather previously created user with filters
  openstack.cloud.identity_user_info:
    cloud: awesomecloud
    name: demouser
    domain: admindomain
    filters:
      is_enabled: False
'''

RETURN = r'''
users:
  description: Dictionary describing all matching identity users.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Unique UUID.
      type: str
    name:
      description: Username of the user.
      type: str
    default_project_id:
      description: Default project ID of the user
      type: str
    description:
      description: The description of this user
      type: str
    domain_id:
      description: Domain ID containing the user
      type: str
    email:
      description: Email of the user
      type: str
    is_enabled:
      description: Flag to indicate if the user is enabled
      type: bool
    links:
      description: The links for the user resource
      type: dict
    password:
      description: The default form of credential used during authentication.
      type: str
    password_expires_at:
      description: The date and time when the password expires. The time zone
                   is UTC. A Null value means the password never expires.
      type: str
    username:
      description: Username with Identity API v2 (OpenStack Pike or earlier)
                   else Null.
      type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class IdentityUserInfoModule(OpenStackModule):
    argument_spec = dict(
        domain=dict(),
        filters=dict(type='dict'),
        name=dict(),
    )
    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        name = self.params['name']
        filters = self.params['filters'] or {}

        kwargs = {}
        domain_name_or_id = self.params['domain']
        if domain_name_or_id:
            domain = self.conn.identity.find_domain(domain_name_or_id)
            if domain is None:
                self.exit_json(changed=False, groups=[])
            kwargs['domain_id'] = domain['id']

        self.exit_json(changed=False,
                       users=[u.to_dict(computed=False)
                              for u in self.conn.search_users(name, filters,
                                                              **kwargs)])


def main():
    module = IdentityUserInfoModule()
    module()


if __name__ == '__main__':
    main()
