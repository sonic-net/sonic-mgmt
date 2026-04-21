#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 by Open Telekom Cloud, operated by T-Systems International GmbH
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: volume_backup
short_description: Add/Delete Volume backup
author: OpenStack Ansible SIG
description:
  - Add or Remove Volume Backup in OpenStack.
options:
  description:
    description:
      - String describing the backup
    type: str
    aliases: ['display_description']
  force:
    description:
      - Indicates whether to backup, even if the volume is attached.
    type: bool
    default: False
  is_incremental:
    description: The backup mode
    type: bool
    default: False
    aliases: ['incremental']
  metadata:
    description: Metadata for the backup
    type: dict
  name:
    description:
      - Name that has to be given to the backup
    required: true
    type: str
    aliases: ['display_name']
  snapshot:
    description: Name or ID of the Snapshot to take backup of.
    type: str
  state:
    description:
      - Should the resource be present or absent.
    choices: [present, absent]
    default: present
    type: str
  volume:
    description:
      - Name or ID of the volume.
      - Required when I(state) is C(present).
    type: str
notes:
    - This module does not support updates to existing backups.
extends_documentation_fragment:
- openstack.cloud.openstack
'''

RETURN = r'''
backup:
    description: Same as C(volume_backup), kept for backward compatibility.
    returned: On success when C(state=present)
    type: dict
volume_backup:
    description: Dictionary describing the volume backup.
    returned: On success when C(state=present)
    type: dict
    contains:
        availability_zone:
            description: Backup availability zone.
            type: str
        container:
            description: The container name.
            type: str
        created_at:
            description: Backup creation time.
            type: str
        data_timestamp:
            description: The time when the data on the volume was first saved.
                         If it is a backup from volume, it will be the same as
                         C(created_at) for a backup. If it is a backup from a
                         snapshot, it will be the same as created_at for the
                         snapshot.
            type: str
        description:
            description: Backup desciption.
            type: str
        fail_reason:
            description: Backup fail reason.
            type: str
        force:
            description: Force backup.
            type: bool
        has_dependent_backups:
            description: If this value is true, there are other backups
                         depending on this backup.
            type: bool
        id:
            description: Unique UUID.
            type: str
            sample: "39007a7e-ee4f-4d13-8283-b4da2e037c69"
        is_incremental:
            description: Backup incremental property.
            type: bool
        links:
            description: A list of links associated with this volume.
            type: list
        metadata:
            description: Backup metadata.
            type: dict
        name:
            description: Backup Name.
            type: str
        object_count:
            description: backup object count.
            type: int
        project_id:
            description: The UUID of the owning project.
            type: str
        size:
            description: The size of the volume, in gibibytes (GiB).
            type: int
        snapshot_id:
            description: Snapshot ID.
            type: str
        status:
            description: Backup status.
            type: str
        updated_at:
            description: Backup update time.
            type: str
        user_id:
            description: The UUID of the project owner.
            type: str
        volume_id:
            description: Volume ID.
            type: str
'''

EXAMPLES = r'''
- name: Create backup
  openstack.cloud.volume_backup:
    name: test_volume_backup
    volume: "test_volume"

- name: Create backup from snapshot
  openstack.cloud.volume_backup:
    name: test_volume_backup
    snapshot: "test_snapshot"
    volume: "test_volume"

- name: Delete volume backup
  openstack.cloud.volume_backup:
    name: test_volume_backup
    state: absent
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class VolumeBackupModule(OpenStackModule):

    argument_spec = dict(
        description=dict(aliases=['display_description']),
        force=dict(default=False, type='bool'),
        is_incremental=dict(default=False,
                            type='bool',
                            aliases=['incremental']),
        metadata=dict(type='dict'),
        name=dict(required=True, aliases=['display_name']),
        snapshot=dict(),
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

        backup = self.conn.block_storage.find_backup(name)

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, backup))

        if state == 'present' and not backup:
            backup = self._create()
            self.exit_json(changed=True,
                           backup=backup.to_dict(computed=False),
                           volume_backup=backup.to_dict(computed=False))

        elif state == 'present' and backup:
            # We do not support backup updates, because
            # openstacksdk does not support it either
            self.exit_json(changed=False,
                           backup=backup.to_dict(computed=False),
                           volume_backup=backup.to_dict(computed=False))

        elif state == 'absent' and backup:
            self._delete(backup)
            self.exit_json(changed=True)

        else:  # state == 'absent' and not backup
            self.exit_json(changed=False)

    def _create(self):
        args = dict()
        for k in ['description', 'is_incremental', 'force', 'metadata',
                  'name']:
            if self.params[k] is not None:
                args[k] = self.params[k]

        volume_name_or_id = self.params['volume']
        volume = self.conn.block_storage.find_volume(volume_name_or_id,
                                                     ignore_missing=False)
        args['volume_id'] = volume.id

        snapshot_name_or_id = self.params['snapshot']
        if snapshot_name_or_id:
            snapshot = self.conn.block_storage.find_snapshot(
                snapshot_name_or_id, ignore_missing=False)
            args['snapshot_id'] = snapshot.id

        backup = self.conn.block_storage.create_backup(**args)

        if self.params['wait']:
            backup = self.conn.block_storage.wait_for_status(
                backup, status='available', wait=self.params['timeout'])

        return backup

    def _delete(self, backup):
        self.conn.block_storage.delete_backup(backup)
        if self.params['wait']:
            self.conn.block_storage.wait_for_delete(
                backup, wait=self.params['timeout'])

    def _will_change(self, state, backup):
        if state == 'present' and not backup:
            return True
        elif state == 'present' and backup:
            # We do not support backup updates, because
            # openstacksdk does not support it either
            return False
        elif state == 'absent' and backup:
            return True
        else:
            # state == 'absent' and not backup:
            return False


def main():
    module = VolumeBackupModule()
    module()


if __name__ == '__main__':
    main()
