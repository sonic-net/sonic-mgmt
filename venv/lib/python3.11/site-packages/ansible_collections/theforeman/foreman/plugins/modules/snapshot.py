#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2019 Manisha Singhal (ATIX AG)
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
module: snapshot
version_added: 1.0.0
short_description: Manage Snapshots
description:
  - "Manage Snapshots for Host Entities"
  - "This module can create, update, revert and delete snapshots"
  - "This module requires the foreman_snapshot_management plugin set up in the server"
  - "See: U(https://github.com/ATIX-AG/foreman_snapshot_management)"
author:
  - "Manisha Singhal (@Manisha15) ATIX AG"
options:
  name:
    description:
      - Name of Snapshot
    required: true
    type: str
  description:
    description:
      - Description of Snapshot
    required: false
    type: str
  host:
    description:
      - Name of related Host
    required: true
    type: str
  include_ram:
    description:
      - Option to add RAM (only available for VMWare compute-resource)
    required: false
    type: bool
  quiesce:
    description:
      - Option to create quiesce snapshot (only available for VMWare compute-resource)
    required: false
    type: bool
  state:
    description:
      - State of Snapshot
    default: present
    choices: ["present", "reverted", "absent", "new_snapshot"]
    type: str
  id:
    description:
      - Id of Snapshot
    required: false
    type: str
extends_documentation_fragment:
  - theforeman.foreman.foreman
'''

EXAMPLES = '''
- name: "Create a Snapshot"
  theforeman.foreman.snapshot:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "snapshot_before_software_upgrade"
    host: "server.example.com"
    state: present

- name: "Create Snapshots with same name"
  theforeman.foreman.snapshot:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "snapshot_before_software_upgrade"
    host: "server.example.com"
    state: new_snapshot

- name: "Update a Snapshot"
  theforeman.foreman.snapshot:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "snapshot_before_software_upgrade"
    host: "server.example.com"
    description: "description of snapshot"
    state: present

- name: "Update a Snapshot with same name"
  theforeman.foreman.snapshot:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "snapshot_before_software_upgrade"
    host: "server.example.com"
    description: "description of snapshot"
    state: present
    id: "snapshot-id"

- name: "Revert a Snapshot"
  theforeman.foreman.snapshot:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "snapshot_before_software_upgrade"
    host: "server.example.com"
    state: reverted

- name: "Delete a Snapshot"
  theforeman.foreman.snapshot:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "snapshot_before_software_upgrade"
    host: "server.example.com"
    state: absent
'''

RETURN = '''
entity:
  description: Final state of the affected entities grouped by their type.
  returned: success
  type: dict
  contains:
    snapshots:
      description: List of snapshots.
      type: list
      elements: dict
'''


from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import ForemanEntityAnsibleModule


class ForemanSnapshotModule(ForemanEntityAnsibleModule):
    pass


def main():
    module = ForemanSnapshotModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent', 'reverted', 'new_snapshot']),
        ),
        foreman_spec=dict(
            host=dict(type='entity', required=True, ensure=False),
            name=dict(required=True),
            description=dict(),
            include_ram=dict(type='bool'),
            id=dict(),
            quiesce=dict(type='bool'),
        ),
        required_plugins=[('snapshot_management', ['*'])],
        entity_opts={'scope': ['host']},
    )

    with module.api_connection():
        host_val = module.lookup_entity('host')
        params = {'host_id': host_val['id']}
        if module.state == 'new_snapshot':
            module.ensure_entity('snapshots', module.foreman_params, None, params=params)
        elif module.state != 'new_snapshot' and module.foreman_params.get('id'):
            snapshot = module.resource_action('snapshots', 'show', params={'id': module.params['id'], 'host_id': host_val['id']})
            module.ensure_entity('snapshots', module.foreman_params, snapshot, params=params, state=module.state)
        else:
            module.run()


if __name__ == '__main__':
    main()
