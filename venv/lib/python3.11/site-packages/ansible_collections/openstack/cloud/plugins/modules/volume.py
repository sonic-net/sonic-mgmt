#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: volume
short_description: Create/Delete Cinder Volumes
author: OpenStack Ansible SIG
description:
   - Create or Remove cinder block storage volumes
options:
   availability_zone:
     description:
       - The availability zone.
     type: str
   description:
     description:
       - String describing the volume
     type: str
     aliases: [display_description]
   image:
     description:
       - Image name or id for boot from volume
       - Mutually exclusive with I(snapshot) and I(volume)
     type: str
   is_bootable:
     description:
       - Bootable flag for volume.
     type: bool
     default: False
     aliases: [bootable]
   is_multiattach:
     description:
       - Whether volume will be sharable or not.
       - To enable this volume to attach to more than one server, set
         I(is_multiattach) to C(true).
       - Note that support for multiattach volumes depends on the volume
         type being used.
       - "Cinder's default for I(is_multiattach) is C(false)."
     type: bool
   metadata:
     description:
       - Metadata for the volume
     type: dict
   name:
     description:
        - Name of volume
     required: true
     type: str
     aliases: [display_name]
   scheduler_hints:
     description:
       - Scheduler hints passed to volume API in form of dict
     type: dict
   size:
     description:
        - Size of volume in GB. This parameter is required when the
          I(state) parameter is 'present'.
     type: int
   snapshot:
     description:
       - Volume snapshot name or id to create from
       - Mutually exclusive with I(image) and I(volume)
     type: str
     aliases: [snapshot_id]
   state:
     description:
       - Should the resource be present or absent.
     choices: [present, absent]
     default: present
     type: str
   volume:
     description:
       - Volume name or id to create from
       - Mutually exclusive with I(image) and I(snapshot)
     type: str
   volume_type:
     description:
       - Volume type for volume
     type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
# Creates a new volume
- name: create 40g test volume
  openstack.cloud.volume:
    state: present
    cloud: mordred
    availability_zone: az2
    size: 40
    name: test_volume
    scheduler_hints:
      same_host: 243e8d3c-8f47-4a61-93d6-7215c344b0c0
'''

RETURN = '''
volume:
  description: Cinder's representation of the volume object
  returned: always
  type: dict
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
    is_multiattach:
      description: Whether this volume can be attached to more than one
                   server.
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
'''
from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class VolumeModule(OpenStackModule):
    argument_spec = dict(
        availability_zone=dict(),
        description=dict(aliases=['display_description']),
        image=dict(),
        is_bootable=dict(type='bool', default=False, aliases=['bootable']),
        is_multiattach=dict(type='bool'),
        metadata=dict(type='dict'),
        name=dict(required=True, aliases=['display_name']),
        scheduler_hints=dict(type='dict'),
        size=dict(type='int'),
        snapshot=dict(aliases=['snapshot_id']),
        state=dict(default='present', choices=['absent', 'present'], type='str'),
        volume=dict(),
        volume_type=dict(),
    )

    module_kwargs = dict(
        supports_check_mode=True,
        mutually_exclusive=[
            ['image', 'snapshot', 'volume'],
        ],
        required_if=[
            ['state', 'present', ['size']],
        ],
    )

    def _build_update(self, volume):
        keys = ('size',)
        return {k: self.params[k] for k in keys if self.params[k] is not None
                and self.params[k] != volume[k]}

    def _update(self, volume):
        '''
        modify volume, the only modification to an existing volume
        available at the moment is extending the size, this is
        limited by the openstacksdk and may change whenever the
        functionality is extended.
        '''
        diff = {'before': volume.to_dict(computed=False), 'after': ''}
        diff['after'] = diff['before']

        update = self._build_update(volume)

        if not update:
            self.exit_json(changed=False,
                           volume=volume.to_dict(computed=False), diff=diff)

        if self.ansible.check_mode:
            volume.size = update['size']
            self.exit_json(changed=False,
                           volume=volume.to_dict(computed=False), diff=diff)

        if 'size' in update and update['size'] != volume.size:
            size = update['size']
            self.conn.volume.extend_volume(volume.id, size)
            volume = self.conn.block_storage.get_volume(volume)

        volume = volume.to_dict(computed=False)
        diff['after'] = volume
        self.exit_json(changed=True, volume=volume, diff=diff)

    def _build_create_kwargs(self):
        keys = ('availability_zone', 'is_multiattach', 'size', 'name',
                'description', 'volume_type', 'scheduler_hints', 'metadata')
        kwargs = {k: self.params[k] for k in keys
                  if self.params[k] is not None}

        find_filters = {}

        if self.params['snapshot']:
            snapshot = self.conn.block_storage.find_snapshot(
                self.params['snapshot'], ignore_missing=False, **find_filters)
            kwargs['snapshot_id'] = snapshot.id

        if self.params['image']:
            image = self.conn.image.find_image(
                self.params['image'], ignore_missing=False)
            kwargs['image_id'] = image.id

        if self.params['volume']:
            volume = self.conn.block_storage.find_volume(
                self.params['volume'], ignore_missing=False, **find_filters)
            kwargs['source_volume_id'] = volume.id

        return kwargs

    def _create(self):
        diff = {'before': '', 'after': ''}
        volume_args = self._build_create_kwargs()

        if self.ansible.check_mode:
            diff['after'] = volume_args
            self.exit_json(changed=True, volume=volume_args, diff=diff)

        volume = self.conn.block_storage.create_volume(**volume_args)
        if self.params['wait']:
            self.conn.block_storage.wait_for_status(
                volume, wait=self.params['timeout'])

        volume = volume.to_dict(computed=False)
        diff['after'] = volume
        self.exit_json(changed=True, volume=volume, diff=diff)

    def _delete(self, volume):
        diff = {'before': '', 'after': ''}
        if volume is None:
            self.exit_json(changed=False, diff=diff)

        diff['before'] = volume.to_dict(computed=False)

        if self.ansible.check_mode:
            self.exit_json(changed=True, diff=diff)

        self.conn.block_storage.delete_volume(volume)
        if self.params['wait']:
            self.conn.block_storage.wait_for_delete(
                volume, wait=self.params['timeout'])
        self.exit_json(changed=True, diff=diff)

    def run(self):
        state = self.params['state']
        volume = self.conn.block_storage.find_volume(self.params['name'])

        if state == 'present':
            if not volume:
                self._create()
            else:
                self._update(volume)
        if state == 'absent':
            self._delete(volume)


def main():
    module = VolumeModule()
    module()


if __name__ == '__main__':
    main()
