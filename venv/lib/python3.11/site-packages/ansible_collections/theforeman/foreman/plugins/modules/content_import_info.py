#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2024, Partha Aji
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
module: content_import_info
version_added: 4.1.0
short_description: List content imports
description:
    - List information about content imports.
author:
    - "Partha Aji (@parthaa)"
options:
  id:
    description:
      - Import history identifier.
    required: false
    type: int
  content_view_version:
    description:
      - Content view version.
    required: false
    type: str
  content_view:
    description:
      - Content view name.
    required: false
    type: str
  type:
    description:
      - Specify complete or incremental imports.
    required: false
    type: str
    choices:
    - complete
    - incremental
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.katelloinfomodule
  - theforeman.foreman.foreman.infomodulewithoutname
'''

EXAMPLES = '''
- name: "List all imports in the organization"
  theforeman.foreman.content_import_info:
    organization: "Default Organization"
    type: complete
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
- name: "Get a specific import history entry"
  theforeman.foreman.content_import_info:
    id: 29
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
- name: "List all imports of a specific content view version"
  theforeman.foreman.content_import_info:
    content_view: RHEL8
    content_view_version: '1.0'
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
- name: "List incremental imports of a specific content view"
  theforeman.foreman.content_import_info:
    content_view: RHEL8
    type: incremental
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import KatelloInfoAnsibleModule


class KatelloContentImportInfo(KatelloInfoAnsibleModule):
    pass


def main():
    module = KatelloContentImportInfo(
        foreman_spec=dict(
            id=dict(required=False, type='int'),
            content_view_version=dict(type='entity', scope=['content_view'], required=False),
            content_view=dict(type='entity', scope=['organization'], required=False),
            type=dict(required=False, type='str', choices=['complete', 'incremental']),
            name=dict(invisible=True),
        ),
    )

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
