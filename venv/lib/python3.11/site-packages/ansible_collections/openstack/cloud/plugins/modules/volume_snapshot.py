#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016, Mario Santos <mario.rf.santos@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: volume_snapshot
short_description: Create/Delete Cinder Volume Snapshots
author: OpenStack Ansible SIG
description:
   - Create or Delete cinder block storage volume snapshots
options:
  description:
    description:
      - String describing the snapshot
    aliases: ['display_description']
    type: str
  force:
    description:
       - Allows or disallows snapshot of a volume to be created,
         when the volume is attached to an instance.
    type: bool
    default: 'false'
  name:
    description:
      - Name of the snapshot
    required: true
    aliases: ['display_name']
    type: str
  state:
    description:
      - Should the snapshot be C(present) or C(absent).
    choices: [present, absent]
    default: present
    type: str
  volume:
    description:
      - Volume name or ID to create the snapshot from.
      - Required when I(state) is C(present).
    type: str
notes:
    - Updating existing volume snapshots has not been implemented yet.
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: create snapshot
  openstack.cloud.volume_snapshot:
    state: present
    cloud: mordred
    name: test_snapshot
    volume: test_volume
- name: delete snapshot
  openstack.cloud.volume_snapshot:
    state: absent
    cloud: mordred
    name: test_snapshot
    volume: test_volume
'''

RETURN = r'''
snapshot:
    description: Same as C(volume_snapshot), kept for backward compatibility.
    returned: On success when C(state=present)
    type: dict
volume_snapshot:
    description: The snapshot instance
    returned: success
    type: dict
    contains:
        created_at:
            description: Snapshot creation time.
            type: str
        description:
            description: Snapshot desciption.
            type: str
        id:
            description: Unique UUID.
            type: str
            sample: "39007a7e-ee4f-4d13-8283-b4da2e037c69"
        is_forced:
            description: Indicate whether to create snapshot,
                         even if the volume is attached.
            type: bool
        metadata:
            description: Snapshot metadata.
            type: dict
        name:
            description: Snapshot Name.
            type: str
        progress:
            description: The percentage of completeness the snapshot is
                         currently at.
            type: str
        project_id:
            description: The project ID this snapshot is associated with.
            type: str
        size:
            description: The size of the volume, in GBs.
            type: int
        status:
            description: Snapshot status.
            type: str
        updated_at:
            description: Snapshot update time.
            type: str
        volume_id:
            description: Volume ID.
            type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class VolumeSnapshotModule(OpenStackModule):
    argument_spec = dict(
        description=dict(aliases=['display_description']),
        name=dict(required=True, aliases=['display_name']),
        force=dict(default=False, type='bool'),
        state=dict(default='present', choices=['absent', 'present']),
        volume=dict(),
    )

    module_kwargs = dict(
        required_if=[
            ('state', 'present', ['volume'])
        ],
        supports_check_mode=True
    )

    def run(self):
        name = self.params['name']
        state = self.params['state']

        snapshot = self.conn.block_storage.find_snapshot(name)

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, snapshot))

        if state == 'present' and not snapshot:
            snapshot = self._create()
            self.exit_json(changed=True,
                           snapshot=snapshot.to_dict(computed=False),
                           volume_snapshot=snapshot.to_dict(computed=False))

        elif state == 'present' and snapshot:
            # We do not support snapshot updates yet
            # TODO: Implement module updates
            self.exit_json(changed=False,
                           snapshot=snapshot.to_dict(computed=False),
                           volume_snapshot=snapshot.to_dict(computed=False))

        elif state == 'absent' and snapshot:
            self._delete(snapshot)
            self.exit_json(changed=True)

        else:  # state == 'absent' and not snapshot
            self.exit_json(changed=False)

    def _create(self):
        args = dict()
        for k in ['description', 'force', 'name']:
            if self.params[k] is not None:
                args[k] = self.params[k]

        volume_name_or_id = self.params['volume']
        volume = self.conn.block_storage.find_volume(volume_name_or_id,
                                                     ignore_missing=False)
        args['volume_id'] = volume.id

        snapshot = self.conn.block_storage.create_snapshot(**args)

        if self.params['wait']:
            snapshot = self.conn.block_storage.wait_for_status(
                snapshot, wait=self.params['timeout'])

        return snapshot

    def _delete(self, snapshot):
        self.conn.block_storage.delete_snapshot(snapshot)
        if self.params['wait']:
            self.conn.block_storage.wait_for_delete(
                snapshot, wait=self.params['timeout'])

    def _will_change(self, state, snapshot):
        if state == 'present' and not snapshot:
            return True
        elif state == 'present' and snapshot:
            # We do not support snapshot updates yet
            # TODO: Implement module updates
            return False
        elif state == 'absent' and snapshot:
            return True
        else:
            # state == 'absent' and not snapshot:
            return False


def main():
    module = VolumeSnapshotModule()
    module()


if __name__ == '__main__':
    main()
