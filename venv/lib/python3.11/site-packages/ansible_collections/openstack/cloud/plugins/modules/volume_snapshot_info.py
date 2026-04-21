#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 by Open Telekom Cloud, operated by T-Systems International GmbH
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = r'''
---
module: volume_snapshot_info
short_description: Get volume snapshots
author: OpenStack Ansible SIG
description:
  - Get Volume Snapshot info from the Openstack cloud.
options:
  details:
    description: More detailed output
    type: bool
  name:
    description:
      - Name of the Snapshot.
    type: str
  status:
    description:
      - Specifies the snapshot status.
    choices: ['available', 'backing-up', 'creating', 'deleted', 'deleting',
              'error', 'error_deleting', 'restoring', 'unmanaging']
    type: str
  volume:
    description:
      - Name or ID of the volume.
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
volume_snapshots:
    description: List of dictionaries describing volume snapshots.
    type: list
    elements: dict
    returned: always
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

EXAMPLES = r'''
- name: List all snapshots
  openstack.cloud.volume_snapshot_info:

- name: Fetch data about a single snapshot
  openstack.cloud.volume_snapshot_info:
    name: my_fake_snapshot
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class VolumeSnapshotInfoModule(OpenStackModule):
    argument_spec = dict(
        details=dict(type='bool'),
        name=dict(),
        status=dict(choices=['available', 'backing-up', 'creating', 'deleted',
                             'deleting', 'error', 'error_deleting',
                             'restoring', 'unmanaging']),
        volume=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        kwargs = dict((k, self.params[k])
                      for k in ['details', 'name', 'status']
                      if self.params[k] is not None)

        volume_name_or_id = self.params['volume']
        volume = None
        if volume_name_or_id:
            volume = self.conn.block_storage.find_volume(volume_name_or_id)
            if volume:
                kwargs['volume_id'] = volume.id

        if volume_name_or_id and not volume:
            snapshots = []
        else:
            snapshots = [b.to_dict(computed=False)
                         for b in self.conn.block_storage.snapshots(**kwargs)]

        self.exit_json(changed=False, volume_snapshots=snapshots)


def main():
    module = VolumeSnapshotInfoModule()
    module()


if __name__ == '__main__':
    main()
