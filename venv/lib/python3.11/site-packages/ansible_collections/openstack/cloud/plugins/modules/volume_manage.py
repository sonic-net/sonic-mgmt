#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 by Pure Storage, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: volume_manage
short_description: Manage/Unmanage Volumes
author: OpenStack Ansible SIG
description:
  - Manage or Unmanage Volume in OpenStack.
options:
  description:
    description:
      - String describing the volume
    type: str
  metadata:
    description: Metadata for the volume
    type: dict
  name:
    description:
      - Name of the volume to be unmanaged or
        the new name of a managed volume
      - When I(state) is C(absent) this must be
        the cinder volume ID
    required: true
    type: str
  state:
    description:
      - Should the resource be present or absent.
    choices: [present, absent]
    default: present
    type: str
  bootable:
    description:
      - Bootable flag for volume.
    type: bool
    default: False
  volume_type:
    description:
      - Volume type for volume
    type: str
  availability_zone:
    description:
      - The availability zone.
    type: str
  host:
    description:
      - Cinder host on which the existing volume resides
      - Takes the form "host@backend-name#pool"
      - Required when I(state) is C(present).
    type: str
  source_name:
    description:
      - Name of existing volume
    type: str
  source_id:
    description:
      - Identifier of existing volume
    type: str
extends_documentation_fragment:
- openstack.cloud.openstack
"""

RETURN = r"""
volume:
  description: Cinder's representation of the volume object
  returned: always
  type: dict
  contains:
    attachments:
      description: Instance attachment information. For a amanaged volume, this
                   will always be empty.
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
"""

EXAMPLES = r"""
- name: Manage volume
  openstack.cloud.volume_manage:
    name: newly-managed-vol
    source_name: manage-me
    host: host@backend-name#pool

- name: Unmanage volume
  openstack.cloud.volume_manage:
    name: "5c831866-3bb3-4d67-a7d3-1b90880c9d18"
    state: absent
"""

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule,
)


class VolumeManageModule(OpenStackModule):

    argument_spec = dict(
        description=dict(type="str"),
        metadata=dict(type="dict"),
        source_name=dict(type="str"),
        source_id=dict(type="str"),
        availability_zone=dict(type="str"),
        host=dict(type="str"),
        bootable=dict(default="false", type="bool"),
        volume_type=dict(type="str"),
        name=dict(required=True, type="str"),
        state=dict(
            default="present", choices=["absent", "present"], type="str"
        ),
    )

    module_kwargs = dict(
        required_if=[("state", "present", ["host"])],
        supports_check_mode=True,
    )

    def run(self):
        name = self.params["name"]
        state = self.params["state"]
        changed = False

        if state == "present":
            changed = True
            if not self.ansible.check_mode:
                volumes = self._manage_list()
                manageable = volumes["manageable-volumes"]
                safe_to_manage = self._is_safe_to_manage(
                    manageable, self.params["source_name"]
                )
                if not safe_to_manage:
                    self.exit_json(changed=False)
                volume = self._manage()
                if volume:
                    self.exit_json(
                        changed=changed, volume=volume.to_dict(computed=False)
                    )
                else:
                    self.exit_json(changed=False)
            else:
                self.exit_json(changed=changed)

        else:
            volume = self.conn.block_storage.find_volume(name)
            if volume:
                changed = True
                if not self.ansible.check_mode:
                    self._unmanage()
                    self.exit_json(changed=changed)
            else:
                self.exit_json(changed=changed)

    def _is_safe_to_manage(self, manageable_list, target_name):
        entry = next(
            (
                v
                for v in manageable_list
                if isinstance(v.get("reference"), dict)
                and (
                    v["reference"].get("name") == target_name
                    or v["reference"].get("source-name") == target_name
                )
            ),
            None,
        )
        if entry is None:
            return False
        return entry.get("safe_to_manage", False)

    def _manage(self):
        kwargs = {
            key: self.params[key]
            for key in [
                "description",
                "bootable",
                "volume_type",
                "availability_zone",
                "host",
                "metadata",
                "name",
            ]
            if self.params.get(key) is not None
        }
        kwargs["ref"] = {}
        if self.params["source_name"]:
            kwargs["ref"]["source-name"] = self.params["source_name"]
        if self.params["source_id"]:
            kwargs["ref"]["source-id"] = self.params["source_id"]

        volume = self.conn.block_storage.manage_volume(**kwargs)

        return volume

    def _manage_list(self):
        response = self.conn.block_storage.get(
            "/manageable_volumes?host=" + self.params["host"],
            microversion="3.8",
        )
        response.raise_for_status()
        manageable_volumes = response.json()
        return manageable_volumes

    def _unmanage(self):
        self.conn.block_storage.unmanage_volume(self.params["name"])


def main():
    module = VolumeManageModule()
    module()


if __name__ == "__main__":
    main()
