#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) Evgeni Golov
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
module: flatpak_remote_repository_mirror
version_added: 5.5.0
short_description: Mirror a Flatpak Remote Repository
description:
  - Mirror a Flatpak Remote Repository to a Product
author:
  - "Evgeni Golov (@evgeni)"
options:
  flatpak_remote:
    description:
    - Flatpak remote
    required: true
    type: str
  flatpak_remote_repository:
    description:
    - Flatpak remote repository
    required: true
    type: str
  product:
    description:
    - Product to mirror the remote repository to
    required: true
    type: str

extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.organization
'''

EXAMPLES = '''
- name: "Mirror flatpak remote repository into product"
  theforeman.foreman.flatpak_remote_repository_mirror:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    product: "My Product"
    flatpak_remote: "rhel"
    flatpak_remote_repository: "rhel9/flatpak-runtime"
'''

RETURN = ''' # '''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import KatelloAnsibleModule


def main():
    module = KatelloAnsibleModule(
        foreman_spec=dict(
            flatpak_remote=dict(type='entity', scope=['organization'], required=True),
            flatpak_remote_repository=dict(type='entity', scope=['flatpak_remote'], required=True),
            product=dict(type='entity', scope=['organization'], required=True, thin=False),
        ),
    )

    module.task_timeout = 12 * 60 * 60

    with module.api_connection():
        product = module.lookup_entity('product')
        flatpak_remote_repository = module.lookup_entity('flatpak_remote_repository')

        if flatpak_remote_repository['name'] not in map(lambda x: x['name'], product['repositories']):
            task = module.resource_action('flatpak_remote_repositories', 'mirror', {'id': flatpak_remote_repository['id'], 'product_id': product['id']})
        else:
            task = None
        changed = task is not None

        module.exit_json(task=task, changed=changed)


if __name__ == '__main__':
    main()
