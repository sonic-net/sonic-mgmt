#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2022, Jeremy Lenz <jlenz@redhat.com>
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
module: content_export_info
version_added: 3.5.0
short_description: List content exports
description:
    - List information about content exports.
author:
    - "Jeremy Lenz (@jeremylenz)"
options:
  id:
    description:
      - Export history identifier.
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
  destination_server:
    description:
      - Destination server name
    required: false
    type: str
  type:
    description:
      - Specify complete or incremental exports.
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
- name: "List all full exports in the organization"
  theforeman.foreman.content_export_info:
    organization: "Default Organization"
    type: complete
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
- name: "Get a specific export history and register the result for the next task"
  vars:
    organization_name: "Export Org"
  theforeman.foreman.content_export_info:
    id: 29
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
  register: result
- name: "Write metadata.json to disk using data from the previous task"
  vars:
    metadata: "{{ result['content_exports'][0]['metadata'] }}"
  ansible.builtin.copy:
    content: "{{ metadata }}"
    dest: ./metadata.json
- name: "List all exports of a specific content view version"
  theforeman.foreman.content_export_info:
    content_view: RHEL8
    content_view_version: '1.0'
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
- name: "List all exports marked for a specific destination server"
  theforeman.foreman.content_export_info:
    destination_server: "airgapped.example.com"
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
- name: "List incremental exports of a specific content view marked for a specific destination server"
  theforeman.foreman.content_export_info:
    content_view: RHEL8
    destination_server: "airgapped.example.com"
    type: incremental
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
- name: "List all exports of a specific content view marked for a specific destination server"
  theforeman.foreman.content_export_info:
    content_view: RHEL8
    destination_server: "airgapped.example.com"
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import KatelloInfoAnsibleModule


class KatelloContentExportInfo(KatelloInfoAnsibleModule):
    pass


def main():
    module = KatelloContentExportInfo(
        foreman_spec=dict(
            id=dict(required=False, type='int'),
            content_view_version=dict(type='entity', scope=['content_view'], required=False),
            content_view=dict(type='entity', scope=['organization'], required=False),
            destination_server=dict(required=False, type='str'),
            type=dict(required=False, type='str', choices=['complete', 'incremental']),
            name=dict(invisible=True),
        ),
    )

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
