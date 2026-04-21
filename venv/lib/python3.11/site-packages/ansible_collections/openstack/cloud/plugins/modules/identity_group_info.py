#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019, Phillipe Smith <phillipelnx@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: identity_group_info
short_description: Fetch OpenStack identity (Keystone) groups
author: OpenStack Ansible SIG
description:
  - Fetch OpenStack identity (Keystone) groups.
options:
  domain:
    description:
      - Name or ID of the domain containing the group.
    type: str
  filters:
    description:
      - A dictionary of meta data to use for further filtering. Elements of
        this dictionary may be additional dictionaries.
    type: dict
  name:
    description:
      - Name or ID of the group.
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Gather previously created groups
  openstack.cloud.identity_group_info:
    cloud: awesomecloud

- name: Gather previously created groups by name
  openstack.cloud.identity_group_info:
    cloud: awesomecloud
    name: demogroup

- name: Gather previously created groups in a specific domain
  openstack.cloud.identity_group_info:
    cloud: awesomecloud
    domain: admindomain

- name: Gather and filter previously created groups
  openstack.cloud.identity_group_info:
    cloud: awesomecloud
    name: demogroup
    domain: admindomain
    filters:
      is_enabled: False
'''

RETURN = r'''
groups:
  description: Dictionary describing all matching identity groups.
  returned: always
  type: list
  elements: dict
  contains:
    name:
      description: Name given to the group.
      type: str
    description:
      description: Description of the group.
      type: str
    id:
      description: Unique UUID.
      type: str
    domain_id:
      description: Domain ID containing the group (keystone v3 clouds only)
      type: bool
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class IdentityGroupInfoModule(OpenStackModule):
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

        groups = self.conn.search_groups(name, filters, **kwargs)
        self.exit_json(changed=False,
                       groups=[g.to_dict(computed=False) for g in groups])


def main():
    module = IdentityGroupInfoModule()
    module()


if __name__ == '__main__':
    main()
