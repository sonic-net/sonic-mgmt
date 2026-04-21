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
module: flatpak_remote
version_added: 5.5.0
short_description: Manage Flatpak Remotes
description:
  - Manage Flatpak Remotes
author:
  - "Evgeni Golov (@evgeni)"
options:
  description:
    description:
    - Description of the flatpak remote
    required: false
    type: str
  name:
    description:
    - name
    required: true
    type: str
  token:
    description:
    - Token/password for the flatpak remote
    required: false
    type: str
  url:
    description:
    - 'Base URL of the flatpak registry index, like C(https://flatpaks.redhat.io/rhel/), C(https://registry.fedoraproject.org).'
    required: false
    type: str
  remote_username:
    description:
    - Username for the flatpak remote
    required: false
    type: str

extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.entity_state
  - theforeman.foreman.foreman.organization
'''

EXAMPLES = '''
- name: Create Fedora flatpak remote
  theforeman.foreman.flatpak_remote:
    name: "fedora"
    url: "registry.fedoraproject.org"
    organization: "Default Organization"
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
'''

RETURN = '''
entity:
  description: Final state of the affected entities grouped by their type.
  returned: success
  type: dict
  contains:
    flatpak_remotes:
      description: List of flatpak_remotes.
      type: list
      elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import KatelloEntityAnsibleModule


class ForemanFlatpakRemoteModule(KatelloEntityAnsibleModule):
    pass


def main():
    module = ForemanFlatpakRemoteModule(
        foreman_spec=dict(
            name=dict(required=True),
            url=dict(),
            description=dict(),
            remote_username=dict(flat_name="username"),
            token=dict(no_log=True),
        ),
    )

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
