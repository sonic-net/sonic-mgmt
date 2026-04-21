#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: server_volume
short_description: Attach/Detach Volumes from OpenStack VM's
author: OpenStack Ansible SIG
description:
   - Attach or Detach volumes from OpenStack VM's
options:
   device:
     description:
      - Device you want to attach. Defaults to auto finding a device name.
     type: str
   server:
     description:
       - Name or ID of server you want to attach a volume to
     required: true
     type: str
   state:
     description:
       - Should the resource be present or absent.
     choices: [present, absent]
     default: present
     type: str
   volume:
     description:
      - Name or id of volume you want to attach to a server
     required: true
     type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

RETURN = r'''
volume:
  type: dict
  description: Volume that was just attached
  returned: On success when I(state) is present
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
'''

EXAMPLES = r'''
- name: Attaches a volume to a compute host
  openstack.cloud.server_volume:
    state: present
    cloud: mordred
    server: Mysql-server
    volume: mysql-data
    device: /dev/vdb
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


def _system_state_change(state, device):
    """Check if system state would change."""
    return (state == 'present' and not device) \
        or (state == 'absent' and device)


class ServerVolumeModule(OpenStackModule):

    argument_spec = dict(
        server=dict(required=True),
        volume=dict(required=True),
        device=dict(),  # None == auto choose device name
        state=dict(default='present', choices=['absent', 'present']),
    )

    def run(self):
        state = self.params['state']
        wait = self.params['wait']
        timeout = self.params['timeout']

        server = self.conn.compute.find_server(self.params['server'],
                                               ignore_missing=False)
        volume = self.conn.block_storage.find_volume(self.params['volume'],
                                                     ignore_missing=False)

        dev = self.conn.get_volume_attach_device(volume, server.id)

        if self.ansible.check_mode:
            self.exit_json(changed=_system_state_change(state, dev))

        if state == 'present':
            changed = False
            if not dev:
                changed = True
                self.conn.attach_volume(server, volume,
                                        device=self.params['device'],
                                        wait=wait, timeout=timeout)
                # refresh volume object
                volume = self.conn.block_storage.get_volume(volume.id)

            self.exit_json(changed=changed,
                           volume=volume.to_dict(computed=False))

        elif state == 'absent':
            if not dev:
                # Volume is not attached to this server
                self.exit_json(changed=False)

            self.conn.detach_volume(server, volume, wait=wait, timeout=timeout)
            self.exit_json(changed=True)


def main():
    module = ServerVolumeModule()
    module()


if __name__ == '__main__':
    main()
