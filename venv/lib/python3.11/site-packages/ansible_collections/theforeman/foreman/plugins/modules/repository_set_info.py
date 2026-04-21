#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2021 William Bradford Clark
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
module: repository_set_info
version_added: 2.1.0
short_description: Fetch information about Red Hat Repositories
description:
  - Fetch information about Red Hat Repositories
author: "William Bradford Clark (@wbclark)"
options:
  product:
    description:
      - Name of the parent product
    required: false
    type: str
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.katelloinfomodule
  - theforeman.foreman.foreman.infomodule
'''

EXAMPLES = '''
- name: "Find repository set by name and product."
  theforeman.foreman.repository_set_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    name: "Red Hat Enterprise Linux 7 Server (RPMs)"
    product: "Red Hat Enterprise Linux Server"

- name: "Find repository set by label."
  theforeman.foreman.repository_set_info:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    search: 'label = "rhel-7-server-rpms"'
'''

RETURN = '''
repository_set:
  description: Details about the found Red Hat Repository.
  returned: success and I(name) was passed
  type: dict
repository_sets:
  description: List of all found Red Hat Repositories and their details.
  returned: success and I(search) was passed
  type: list
  elements: dict
'''


from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import KatelloInfoAnsibleModule


class KatelloRepositorySetInfo(KatelloInfoAnsibleModule):
    pass


def main():
    module = KatelloRepositorySetInfo(
        foreman_spec=dict(
            product=dict(type='entity', scope=['organization']),
        ),
        entity_opts={'scope': ['product']},
        required_together=[
            ['name', 'product'],
        ],
    )

    # KatelloInfoAnsibleModule automatically adds organization to the entity scope
    # but repository sets are scoped by product (and these are org scoped)
    module.foreman_spec['entity']['scope'].remove('organization')

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
