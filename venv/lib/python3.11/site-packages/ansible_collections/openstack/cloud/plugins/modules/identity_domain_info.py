#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 Hewlett-Packard Enterprise Corporation
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: identity_domain_info
short_description: Fetch identity (Keystone) domains from OpenStack cloud
author: OpenStack Ansible SIG
description:
  - Fetch identity (Keystone) domains from OpenStack cloud
options:
  filters:
    description:
      - A dictionary of meta data to use for filtering.
      - Elements of this dictionary may be additional dictionaries.
    type: dict
  name:
    description:
      - Name or ID of the domain
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Gather information about previously created domain
  openstack.cloud.identity_domain_info:
    cloud: awesomecloud

- name: Gather information about a previously created domain by name
  openstack.cloud.identity_domain_info:
    cloud: awesomecloud
    name: demodomain

- name: Gather information about a previously created domain with filter
  openstack.cloud.identity_domain_info:
    cloud: awesomecloud
    name: demodomain
    filters:
      is_enabled: false
'''

RETURN = r'''
domains:
  description: List of dictionaries describing OpenStack domains
  returned: always
  type: list
  elements: dict
  contains:
    description:
      description: Description of the domain.
      type: str
    id:
      description: Unique UUID.
      type: str
    is_enabled:
      description: Flag to indicate if the domain is enabled.
      type: bool
    links:
      description: The links related to the domain resource
      type: list
    name:
      description: Name given to the domain.
      type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class IdentityDomainInfoModule(OpenStackModule):
    argument_spec = dict(
        filters=dict(type='dict'),
        name=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        kwargs = {}
        name = self.params['name']
        if name is not None:
            kwargs['name_or_id'] = name

        filters = self.params['filters']
        if filters is not None:
            kwargs['filters'] = filters

        self.exit_json(changed=False,
                       domains=[d.to_dict(computed=False)
                                for d in self.conn.search_domains(**kwargs)])


def main():
    module = IdentityDomainInfoModule()
    module()


if __name__ == '__main__':
    main()
