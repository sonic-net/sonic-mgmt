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
module: content_export_version
version_added: 3.6.0
short_description: Manage content view version content exports
description:
    - Export a content view version to a directory.
author:
    - "Jeremy Lenz (@jeremylenz)"
options:
  content_view_version:
    description:
      - Content view version, e.g. "7.0"
    required: true
    type: str
  content_view:
    description:
      - Content view name.
    required: true
    type: str
  destination_server:
    description:
      - Destination server name; optional parameter to differentiate between exports
    required: false
    type: str
  fail_on_missing_content:
    description:
      - Fails if any of the repositories belonging to this version are unexportable.
    required: false
    type: bool
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.organization
  - theforeman.foreman.foreman.katelloexport
'''

EXAMPLES = '''
- name: "Export content view version (full)"
  theforeman.foreman.content_export_version:
    content_view: RHEL8
    content_view_version: '1.0'
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    destination_server: "airgapped.example.com"

- name: "Export content view version (full) in chunks of 10 GB"
  theforeman.foreman.content_export_version:
    content_view: RHEL8
    content_view_version: '1.0'
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    destination_server: "airgapped.example.com"
    chunk_size_gb: 10

- name: "Export content view version (full) and fail if any repos are unexportable"
  theforeman.foreman.content_export_version:
    content_view: RHEL8
    content_view_version: '1.0'
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    destination_server: "airgapped.example.com"
    fail_on_missing_content: true

- name: "Export content view version (incremental) since the most recent export"
  theforeman.foreman.content_export_version:
    content_view: RHEL8
    content_view_version: '1.0'
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    destination_server: "airgapped.example.com"
    incremental: true

- name: "Export content view version (incremental) since a specific export"
  theforeman.foreman.content_export_version:
    content_view: RHEL8
    content_view_version: '1.0'
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    organization: "Default Organization"
    destination_server: "airgapped.example.com"
    incremental: true
    from_history_id: 12345
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import KatelloContentExportBaseModule


class KatelloContentExportModule(KatelloContentExportBaseModule):
    pass


def main():
    module = KatelloContentExportModule(
        foreman_spec=dict(
            content_view_version=dict(type='entity', scope=['content_view'], search_by='version', flat_name='id', required=True),
            content_view=dict(type='entity', scope=['organization'], required=True),
            destination_server=dict(required=False, type='str'),
            fail_on_missing_content=dict(required=False, type='bool'),
        ),
        export_action='version',
    )

    with module.api_connection():
        module.run()


if __name__ == '__main__':
    main()
