#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 Hewlett-Packard Enterprise Corporation
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: project_info
short_description: Retrieve information about one or more OpenStack projects
author: OpenStack Ansible SIG
description:
  - Retrieve information about a one or more OpenStack projects
options:
  name:
    description:
      - Name or ID of the project.
    type: str
  domain:
    description:
      - Name or ID of the domain containing the project.
    type: str
  filters:
    description:
      - A dictionary of meta data to use for filtering projects.
      - Elements of I(filters) are passed as query parameters to
        OpenStack Identity API.
    type: dict
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Fetch all Identity (Keystone) projects
  openstack.cloud.project_info:
    cloud: awesomecloud

- name: Fetch all projects with a name
  openstack.cloud.project_info:
    cloud: awesomecloud
    name: demoproject

- name: Fetch all projects with a name in a domain
  openstack.cloud.project_info:
    cloud: awesomecloud
    name: demoproject
    domain: admindomain

- name: Fetch all disabled projects
  openstack.cloud.project_info:
    cloud: awesomecloud
    filters:
      is_enabled: false
'''

RETURN = r'''
projects:
  description: List of dictionaries describing Identity (Keystone) projects.
  elements: dict
  returned: always, but can be empty
  type: list
  contains:
    description:
      description: Project description
      type: str
      sample: "demodescription"
    domain_id:
      description: Domain ID to which the project belongs
      type: str
      sample: "default"
    id:
      description: Project ID
      type: str
      sample: "f59382db809c43139982ca4189404650"
    is_domain:
      description: Indicates whether the project also acts as a domain.
      type: bool
    is_enabled:
      description: Indicates whether the project is enabled
      type: bool
    name:
      description: Project name
      type: str
      sample: "demoproject"
    options:
      description: The resource options for the project
      type: dict
    parent_id:
      description: The ID of the parent of the project
      type: str
    tags:
      description: A list of associated tags
      type: list
      elements: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class IdentityProjectInfoModule(OpenStackModule):
    argument_spec = dict(
        domain=dict(),
        name=dict(),
        filters=dict(type='dict'),
    )
    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        filters = self.params['filters'] or {}

        domain_name_or_id = self.params['domain']
        if domain_name_or_id is not None:
            domain = self.conn.identity.find_domain(domain_name_or_id)

            if not domain:
                self.exit_json(changed=False, projects=[])

            filters['domain_id'] = domain.id

        projects = self.conn.search_projects(name_or_id=self.params['name'],
                                             filters=filters)

        self.exit_json(changed=False,
                       projects=[p.to_dict(computed=False) for p in projects])


def main():
    module = IdentityProjectInfoModule()
    module()


if __name__ == '__main__':
    main()
