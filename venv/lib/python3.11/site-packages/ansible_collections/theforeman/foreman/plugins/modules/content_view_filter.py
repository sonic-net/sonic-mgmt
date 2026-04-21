#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2018, Sean O'Keeffe <seanokeeffe797@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: content_view_filter
version_added: 1.0.0
short_description: Manage Content View Filters
description:
    - Create and manage content View filters
author: "Sean O'Keeffe (@sean797)"
options:
  name:
    description:
      - Name of the Content View Filter
    type: str
    required: true
  description:
    description:
      - Description of the Content View Filter
    type: str
  content_view:
    description:
      - Name of the content view
    required: true
    type: str
  state:
    description:
      - State of the content view filter
    default: present
    choices:
      - present
      - absent
    type: str
    aliases:
      - filter_state
  repositories:
    description:
      - List of repositories that include name and product
      - An empty Array means all current and future repositories
    default: []
    type: list
    elements: dict
  filter_type:
    description:
      - Content view filter type
    required: true
    choices:
      - rpm
      - package_group
      - erratum
      - docker
      - modulemd
      - deb
    type: str
  inclusion:
    description:
      - Create an include filter
    default: false
    type: bool
  original_packages:
    description:
      - Include all RPMs with no errata
    type: bool
  original_module_streams:
    description:
      - Include all module streams with no errata
      - Only valid on I(filter_type=modulemd).
    type: bool
    version_added: 3.10.0
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.organization
'''

EXAMPLES = '''
# as of v4.0.0 you can no longer manage rules from this module, content_view_filter_rule should be used for that
# you still need to ensure the filter itself exists before adding rules to said filter

- name: Ensure the filter for errata inclusion by date exists
  theforeman.foreman.content_view_filter:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    name: "errata_by_date"
    content_view: "Standard Operating Environment"
    filter_type: rpm
    inclusion: true

- name: Ensure package exclude filter 1 exists
  theforeman.foreman.content_view_filter:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    name: "package filter 1"
    content_view: "Standard Operating Environment"
    filter_type: rpm

- name: Ensure modulemd filter for 389 exists
  theforeman.foreman.content_view_filter:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    name: "modulemd filter"
    content_view: "Standard Operating Environment"
    filter_type: modulemd
'''

RETURN = '''
entity:
  description: Final state of the affected entities grouped by their type.
  returned: success
  type: dict
  contains:
    content_view_filters:
      description: List of content view filters.
      type: list
      elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import KatelloMixin, ForemanEntityAnsibleModule


class KatelloContentViewFilterModule(KatelloMixin, ForemanEntityAnsibleModule):
    pass


def main():
    module = KatelloContentViewFilterModule(
        foreman_spec=dict(
            name=dict(required=True),
            description=dict(),
            repositories=dict(type='entity_list', default=[], elements='dict'),
            inclusion=dict(type='bool', default=False),
            original_packages=dict(type='bool'),
            content_view=dict(type='entity', scope=['organization'], required=True),
            filter_type=dict(required=True, choices=['rpm', 'package_group', 'erratum', 'docker', 'modulemd', 'deb'], flat_name='type'),
            original_module_streams=dict(type='bool'),
        ),
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent'], aliases=['filter_state']),
        ),
        entity_opts=dict(scope=['content_view']),
    )

    with module.api_connection():
        scope = module.scope_for('organization')

        cv_scope = module.scope_for('content_view')
        if module.foreman_params['repositories']:
            repositories = []
            for repo in module.foreman_params['repositories']:
                product = module.find_resource_by_name('products', repo['product'], params=scope, thin=True)
                product_scope = {'product_id': product['id']}
                repositories.append(module.find_resource_by_name('repositories', repo['name'], params=product_scope, thin=True))
            module.foreman_params['repositories'] = repositories

        if not module.desired_absent:
            module.foreman_params.pop('organization')
        entity = module.lookup_entity('entity')
        module.ensure_entity(
            'content_view_filters',
            module.foreman_params,
            entity,
            params=cv_scope,
        )


if __name__ == '__main__':
    main()
