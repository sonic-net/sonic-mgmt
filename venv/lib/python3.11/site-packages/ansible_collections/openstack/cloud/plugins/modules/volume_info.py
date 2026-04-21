#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020, Sagi Shnaidman <sshnaidm@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: volume_info
short_description: Retrieve information about volumes
author: Sagi Shnaidman (@sshnaidm)
description:
  - Get information about block storage in openstack
options:
  all_projects:
    description:
    - Whether to return the volumes in all projects
    type: bool
  details:
    description:
    - Whether to provide additional information about volumes
    type: bool
  name:
    description:
    - Name of the volume
    type: str
    required: false
  status:
    description:
    - Status of the volume so that you can filter on C(available) for example
    type: str
    required: false
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
volumes:
  description: Volumes in project(s)
  returned: always
  type: list
  elements: dict
  contains:
    attachments:
      description: Instance attachment information. If this volume is attached
                   to a server instance, the attachments list includes the UUID
                   of the attached server, an attachment UUID, the name of the
                   attached host, if any, the volume UUID, the device, and the
                   device UUID. Otherwise, this list is empty.
      type: list
    availability_zone:
      description: The name of the availability zone.
      type: str
    consistency_group_id:
      description: The UUID of the consistency group.
      type: str
    created_at:
      description: The date and time when the resource was created.
      type: str
    description:
      description: The volume description.
      type: str
    extended_replication_status:
      description: Extended replication status on this volume.
      type: str
    group_id:
      description: The ID of the group.
      type: str
    host:
      description: The volume's current back-end.
      type: str
    id:
      description: The UUID of the volume.
      type: str
    image_id:
      description: Image on which the volume was based
      type: str
    is_bootable:
      description: Enables or disables the bootable attribute. You can boot an
                   instance from a bootable volume.
      type: str
    is_encrypted:
      description: If true, this volume is encrypted.
      type: bool
    metadata:
      description: A metadata object. Contains one or more metadata key and
                   value pairs that are associated with the volume.
      type: dict
    migration_id:
      description: The volume ID that this volume name on the backend is
                   based on.
      type: str
    migration_status:
      description: The status of this volume migration (None means that a
                   migration is not currently in progress).
      type: str
    name:
      description: The volume name.
      type: str
    project_id:
      description: The project ID which the volume belongs to.
      type: str
    replication_driver_data:
      description: Data set by the replication driver
      type: str
    replication_status:
      description: The volume replication status.
      type: str
    scheduler_hints:
      description: Scheduler hints for the volume
      type: dict
    size:
      description: The size of the volume, in gibibytes (GiB).
      type: int
    snapshot_id:
      description: To create a volume from an existing snapshot, specify the
                   UUID of the volume snapshot. The volume is created in same
                   availability zone and with same size as the snapshot.
      type: str
    source_volume_id:
      description: The UUID of the source volume. The API creates a new volume
                   with the same size as the source volume unless a larger size
                   is requested.
      type: str
    status:
      description: The volume status.
      type: str
    updated_at:
      description: The date and time when the resource was updated.
      type: str
    user_id:
      description: The UUID of the user.
      type: str
    volume_image_metadata:
      description: List of image metadata entries. Only included for volumes
                   that were created from an image, or from a snapshot of a
                   volume originally created from an image.
      type: dict
    volume_type:
      description: The associated volume type name for the volume.
      type: str
  sample:
    - attachments: []
      availability_zone: nova
      consistency_group_id: null
      created_at: '2017-11-15T10:51:19.000000'
      description: ''
      extended_replication_status: null
      group_id: 402ac6ed-527f-4781-8484-7ff4467e34f5
      host: null
      id: 103ac6ed-527f-4781-8484-7ff4467e34f5
      image_id: null
      is_bootable: true
      is_encrypted: false
      metadata:
        readonly: 'False'
      migration_id: null
      migration_status: null
      name: ''
      project_id: cab34702154a42fc96ed9403c691c76e
      replication_driver_data: null
      replication_status: disabled
      scheduler_hints: {}
      size: 9
      snapshot_id: null
      source_volume_id: null
      status: available
      updated_at: '2017-11-15T10:51:19.000000'
      user_id: ac303ed-527f-4781-8484-7ff4467e34f5
      volume_image_metadata:
        checksum: a14e113deeee3a3392462f167ed28cb5
        container_format: bare
        disk_format: raw
        family: centos-7
        image_id: afcf3320-1bf8-4a9a-a24d-5abd639a6e33
        image_name: CentOS-7-x86_64-GenericCloud-1708
        latest: centos-7-latest
        min_disk: '0'
        min_ram: '0'
        official: 'True'
        official-image: 'True'
        size: '8589934592'
      volume_type: null
'''

EXAMPLES = r'''
- openstack.cloud.volume_info:

- openstack.cloud.volume_info:
    name: myvolume

- openstack.cloud.volume_info:
    all_projects: true

- openstack.cloud.volume_info:
    all_projects: true
    details: false
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class VolumeInfoModule(OpenStackModule):

    argument_spec = dict(
        all_projects=dict(type='bool'),
        details=dict(type='bool'),
        name=dict(),
        status=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    def run(self):
        kwargs = dict((k, self.params[k])
                      for k in ['all_projects', 'details', 'name', 'status']
                      if self.params[k] is not None)

        volumes = [v.to_dict(computed=False)
                   for v in self.conn.block_storage.volumes(**kwargs)]

        self.exit_json(changed=False, volumes=volumes)


def main():
    module = VolumeInfoModule()
    module()


if __name__ == '__main__':
    main()
