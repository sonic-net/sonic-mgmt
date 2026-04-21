#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# Copyright: (c) 2023, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# Copyright: (c) 2023, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_backup
short_description: Manages backups
description:
- Manage backups on Cisco ACI Multi-Site.
author:
- Shreyas Srish (@shrsr)
- Lionel Hercot (@lhercot)
- Sabari Jaganathan (@sajagana)
options:
  location_type:
    description:
    - The type of location for the backup to be stored
    type: str
    choices: [ local, remote]
    default: local
  backup:
    description:
    - The name given to the backup
    - C(backup) is mutually exclusive with C(backup_id). Only use one of the two.
    type: str
    aliases: [ name ]
  backup_id:
    description:
    - The id of a specific backup
    - C(backup_id) is mutually exclusive with C(backup). Only use one of the two.
    type: str
    aliases: [ id ]
  remote_location:
    description:
    - The remote location's name where the backup should be stored
    type: str
  remote_path:
   description:
    - This path is relative to the remote location.
    - A '/' is automatically added between the remote location folder and this path.
    - This folder structure should already exist on the remote location.
   type: str
  description:
    description:
    - Brief information about the backup.
    type: str
  destination:
    description:
    - Location where to download the backup to
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(upload) for uploading backup.
    - Use C(restore) for restoring backup.
    - Use C(download) for downloading backup.
    - Use C(move) for moving backup from local to remote location.
    type: str
    choices: [ absent, present, query, upload, restore, download, move ]
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new local backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    description: via Ansible
    location_type: local
    state: present

- name: Create a new remote backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    description: via Ansible
    location_type: remote
    remote_location: ansible_test
    state: present

- name: Move backup to remote location
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup0
    remote_location: ansible_test
    remote_path: test
    state: move

- name: Download a backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    destination: ./
    state: download

- name: Upload a backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: ./Backup
    state: upload

- name: Restore a backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    state: restore

- name: Remove a Backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    state: absent

- name: Query a backup
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup
    state: query
  register: query_result

- name: Query a backup with its complete name
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    backup: Backup_20200721220043
    state: query
  register: query_result

- name: Query all backups
  cisco.mso.mso_backup:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
import os


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        location_type=dict(type="str", default="local", choices=["local", "remote"]),
        description=dict(type="str"),
        backup=dict(type="str", aliases=["name"]),
        backup_id=dict(type="str", aliases=["id"]),
        remote_location=dict(type="str"),
        remote_path=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query", "upload", "restore", "download", "move"]),
        destination=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["location_type", "remote", ["remote_location"]],
            ["state", "absent", ["backup", "backup_id"], True],
            ["state", "present", ["backup"]],
            ["state", "upload", ["backup", "backup_id"], True],
            ["state", "restore", ["backup", "backup_id"], True],
            ["state", "download", ["backup", "backup_id"], True],
            ["state", "download", ["destination"]],
            ["state", "move", ["backup", "backup_id"], True],
            ["state", "move", ["remote_location", "remote_path"]],
        ],
        mutually_exclusive=[
            ("backup", "backup_id"),
        ],
    )

    description = module.params.get("description")
    location_type = module.params.get("location_type")
    state = module.params.get("state")
    backup = module.params.get("backup")
    backup_id = module.params.get("backup_id")
    remote_location = module.params.get("remote_location")
    remote_path = module.params.get("remote_path")
    destination = module.params.get("destination")

    mso = MSOModule(module)

    backup_names = []
    mso.existing = mso.query_objs("backups/backupRecords", key="backupRecords")
    if backup or backup_id:
        if mso.existing:
            data = mso.existing
            mso.existing = []
            for backup_info in data:
                if (backup_id and backup_id == backup_info.get("id")) or (
                    backup and (backup == backup_info.get("name").split("_")[0] or backup == backup_info.get("name"))
                ):
                    mso.existing.append(backup_info)
                    backup_names.append(backup_info.get("name"))

    if state == "query":
        mso.exit_json()

    elif state == "absent":
        mso.previous = mso.existing
        if len(mso.existing) > 1:
            mso.module.fail_json(msg="Multiple backups with same name found. Existing backups with similar names: {0}".format(", ".join(backup_names)))
        elif len(mso.existing) == 1:
            if module.check_mode:
                mso.existing = {}
            else:
                mso.existing = mso.request("backups/backupRecords/{id}".format(id=mso.existing[0].get("id")), method="DELETE")
        mso.exit_json()

    elif state == "present":
        mso.previous = mso.existing

        payload = dict(name=backup, description=description, locationType=location_type)

        if location_type == "remote":
            remote_location_info = mso.lookup_remote_location(remote_location)
            payload.update(remoteLocationId=remote_location_info.get("id"))
            if remote_path:
                remote_path = "{0}/{1}".format(remote_location_info.get("path"), remote_path)
                payload.update(remotePath=remote_path)

        mso.proposed = payload

        if module.check_mode:
            mso.existing = mso.proposed
        else:
            mso.existing = mso.request("backups", method="POST", data=payload)
        mso.exit_json()

    elif state == "upload":
        mso.previous = mso.existing

        if module.check_mode:
            mso.existing = mso.proposed
        else:
            try:
                request_url = "backups/upload"
                payload = dict()
                if mso.platform == "nd":
                    if remote_location is None or remote_path is None:
                        mso.module.fail_json(msg="NDO backup upload failed: remote_location and remote_path are required for NDO backup upload")
                    remote_location_info = mso.lookup_remote_location(remote_location)
                    request_url = "backups/remoteUpload/{0}".format(remote_location_info.get("id"))
                else:
                    payload = dict(name=(os.path.basename(backup), open(backup, "rb"), "application/x-gzip"))

                mso.existing = mso.request_upload(request_url, fields=payload)
            except Exception as error:
                mso.module.fail_json(msg="Upload failed due to: {0}, Backup file: '{1}'".format(error, ", ".join(backup.split("/")[-1:])))
        mso.exit_json()

    if len(mso.existing) == 0:
        mso.module.fail_json(msg="Backup '{0}' does not exist".format(backup))
    elif len(mso.existing) > 1:
        mso.module.fail_json(msg="Multiple backups with same name found. Existing backups with similar names: {0}".format(", ".join(backup_names)))

    elif state == "restore":
        mso.previous = mso.existing
        if module.check_mode:
            mso.existing = mso.proposed
        else:
            mso.existing = mso.request("backups/{id}/restore".format(id=mso.existing[0].get("id")), method="PUT")

    elif state == "download":
        mso.previous = mso.existing
        if module.check_mode:
            mso.existing = mso.proposed
        else:
            mso.existing = mso.request_download("backups/{id}/download".format(id=mso.existing[0].get("id")), destination=destination)

    elif state == "move":
        mso.previous = mso.existing
        remote_location_info = mso.lookup_remote_location(remote_location)
        remote_path = "{0}/{1}".format(remote_location_info.get("path"), remote_path)
        payload = dict(remoteLocationId=remote_location_info.get("id"), remotePath=remote_path, backupRecordId=mso.existing[0].get("id"))
        if module.check_mode:
            mso.existing = mso.proposed
        else:
            mso.existing = mso.request("backups/remote-location", method="POST", data=payload)

    mso.exit_json()


if __name__ == "__main__":
    main()
