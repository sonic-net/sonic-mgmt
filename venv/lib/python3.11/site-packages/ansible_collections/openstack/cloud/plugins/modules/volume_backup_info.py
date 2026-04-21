#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 by Open Telekom Cloud, operated by T-Systems International GmbH
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: volume_backup_info
short_description: Get Backups
author: OpenStack Ansible SIG
description:
  - Get Backup info from the Openstack cloud.
options:
  name:
    description:
      - Name of the Backup.
    type: str
  volume:
    description:
      - Name or ID of the volume.
    type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

RETURN = r'''
volume_backups:
    description: List of dictionaries describing volume backups.
    type: list
    elements: dict
    returned: always.
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
- name: Get all backups
  openstack.cloud.volume_backup_info:

- name: Get backup 'my_fake_backup'
  openstack.cloud.volume_backup_info:
    name: my_fake_backup
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class VolumeBackupInfoModule(OpenStackModule):

    argument_spec = dict(
        name=dict(),
        volume=dict()
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        kwargs = dict((k, self.params[k])
                      for k in ['name']
                      if self.params[k] is not None)

        volume_name_or_id = self.params['volume']
        volume = None
        if volume_name_or_id:
            volume = self.conn.block_storage.find_volume(volume_name_or_id)
            if volume:
                kwargs['volume_id'] = volume.id

        if volume_name_or_id and not volume:
            backups = []
        else:
            backups = [b.to_dict(computed=False)
                       for b in self.conn.block_storage.backups(**kwargs)]

        self.exit_json(changed=False, volume_backups=backups)


def main():
    module = VolumeBackupInfoModule()
    module()


if __name__ == '__main__':
    main()
