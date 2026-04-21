#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2020 Evgeni Golov
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
module: repository_info
version_added: 2.0.0
short_description: Fetch information about Repositories
description:
  - Fetch information about Repositories
author: "Evgeni Golov (@evgeni)"
options:
  product:
    description:
      - Product to which the repository lives in
    required: true
    type: str
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.katelloinfomodule
  - theforeman.foreman.foreman.infomodule
'''

EXAMPLES = '''
- name: "Find repository by name"
  theforeman.foreman.repository_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "My repository"
    product: "My Product"
    organization: "Default Organization"

- name: "Find repository using a search"
  theforeman.foreman.repository_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    product: "My Product"
    organization: "Default Organization"
    search: 'name = "My repository"'
'''

RETURN = '''
repository:
  description: Details about the found repository
  returned: success and I(name) was passed
  type: dict
repositories:
  description: List of all found repositories and their details
  returned: success and I(search) was passed
  type: list
  elements: dict
'''


from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import KatelloInfoAnsibleModule


class KatelloRepositoryInfo(KatelloInfoAnsibleModule):
    pass


def main():
    module = KatelloRepositoryInfo(
        foreman_spec=dict(
            product=dict(type='entity', scope=['organization'], required=True),
        ),
        entity_opts={'scope': ['product']},
    )

    # KatelloInfoAnsibleModule automatically adds organization to the entity scope
    # but repositories are scoped by product (and these are org scoped)
    module.foreman_spec['entity']['scope'].remove('organization')

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
