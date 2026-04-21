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
module: flatpak_remote_scan
version_added: 5.5.0
short_description: Scan a Flatpak Remote
description:
  - Scan a Flatpak Remote
author:
  - "Evgeni Golov (@evgeni)"
options:
  flatpak_remote:
    description:
    - Flatpak remote
    required: true
    type: str

extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.organization
'''

EXAMPLES = '''
- name: "Scan flatpak remote"
  theforeman.foreman.flatpak_remote_scan:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    flatpak_remote: "rhel"
'''

RETURN = ''' # '''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import KatelloAnsibleModule


def main():
    module = KatelloAnsibleModule(
        foreman_spec=dict(
            flatpak_remote=dict(type='entity', scope=['organization'], required=True),
        ),
    )

    module.task_timeout = 12 * 60 * 60

    with module.api_connection():
        flatpak_remote = module.lookup_entity('flatpak_remote')

        task = module.resource_action('flatpak_remotes', 'scan', {'id': flatpak_remote['id']})

        module.exit_json(task=task)


if __name__ == '__main__':
    main()
