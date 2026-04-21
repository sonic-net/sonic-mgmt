#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Florian Paul Azim Hoberg (@gyptazy) <florian.hoberg@credativ.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_storage
version_added: 1.3.0
short_description: Manage storage in PVE clusters and nodes
description:
  - Manage storage in PVE clusters and nodes.
author: Florian Paul Azim Hoberg (@gyptazy)
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
options:
  nodes:
    description:
      - A list of Proxmox VE nodes on which the target storage is enabled.
      - Required when C(state=present).
    type: list
    elements: str
    required: false
  name:
    description:
      - The name of the storage displayed in the storage list.
    type: str
    required: true
  state:
    description:
      - The state of the defined storage type to perform.
    choices: ["present", "absent"]
    type: str
  type:
    description:
      - The storage type/protocol to use when adding the storage.
    type: str
    required: true
    choices: ['cephfs', 'cifs', 'dir', 'iscsi', 'nfs', 'pbs', 'zfspool']
  cephfs_options:
    description:
      - Extended information for adding CephFS storage.
    type: dict
    suboptions:
      monhost:
        description:
          - The hostname or IP address of the monhost.
        type: list
        elements: str
        required: false
      username:
        description:
          - The required username for the storage system.
        type: str
        required: false
      password:
        description:
          - The required password for the storage system.
        type: str
        required: false
      path:
        description:
          - The path to be used within the CephFS.
        type: str
        default: '/'
        required: false
      subdir:
        description:
          - The subdir to be used within the CephFS.
        type: str
        required: false
      client_keyring:
        description:
          - The client keyring to be used.
        type: str
        required: false
      fs_name:
        description:
          - The Ceph filesystem name
        type: str
        required: false
  cifs_options:
    description:
      - Extended information for adding CIFS storage.
    type: dict
    suboptions:
      server:
        description:
          - The hostname or IP address of the remote storage system.
        type: str
        required: false
      username:
        description:
          - The required username for the storage system.
        type: str
        required: false
      password:
        description:
          - The required password for the storage system.
        type: str
        required: false
      share:
        description:
          - The share to be used from the remote storage system.
        type: str
        required: false
      domain:
        description:
          - The required domain for the CIFS share.
        type: str
        required: false
      smb_version:
        description:
          - The minimum SMB version to use for.
        type: str
        required: false
  dir_options:
    description:
      - Extended information for adding Directory storage.
    type: dict
    suboptions:
      path:
        description:
          - The path of the direcotry on the node(s).
        type: str
        required: false
  nfs_options:
    description:
      - Extended information for adding NFS storage.
    type: dict
    suboptions:
      server:
        description:
          - The hostname or IP address of the remote storage system.
        type: str
        required: false
      export:
        description:
          - The required NFS export path.
        type: str
        required: false
      options:
        description:
          - Additional NFS related mount options (e.g., version, pNFS).
        type: str
        required: false
  iscsi_options:
    description:
      - Extended information for adding iSCSI storage.
    type: dict
    suboptions:
      portal:
        description:
          - The hostname or IP address of the remote storage system as the portal address.
        type: str
        required: false
      target:
        description:
          - The required iSCSI target.
        type: str
        required: false
  pbs_options:
    description:
      - Extended information for adding Proxmox Backup Server as storage.
    type: dict
    suboptions:
      server:
        description:
          - The hostname or IP address of the Proxmox Backup Server.
        type: str
        required: false
      username:
        description:
          - The required username for the Proxmox Backup Server.
        type: str
        required: false
      password:
        description:
          - The required password for the Proxmox Backup Server.
        type: str
        required: false
      datastore:
        description:
          - The required datastore to use from the Proxmox Backup Server.
        type: str
        required: false
      fingerprint:
        description:
          - The required fingerprint of the Proxmox Backup Server system.
        type: str
        required: false
  zfspool_options:
    description:
      - Extended information for adding ZFS storage.
    type: dict
    suboptions:
      pool:
        description:
          - The name of the ZFS pool to use.
        type: str
        required: false
  content:
    description:
      - The desired content that should be used with this storage type.
      - Required when C(state=present).
    type: list
    required: false
    elements: str
    choices: ["images", "snippets", "import", "iso", "backup", "rootdir", "vztmpl"]
extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
"""

EXAMPLES = r"""
- name: Add PBS storage to Proxmox VE Cluster
  community.proxmox.proxmox_storage:
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    validate_certs: false
    nodes: ["de-cgn01-virt01", "de-cgn01-virt02"]
    state: present
    name: backup-backupserver01
    type: pbs
    pbs_options:
      server: proxmox-backup-server.example.com
      username: backup@pbs
      password: password123
      datastore: backup
      fingerprint: "F3:04:D2:C1:33:B7:35:B9:88:D8:7A:24:85:21:DC:75:EE:7C:A5:2A:55:2D:99:38:6B:48:5E:CA:0D:E3:FE:66"
      export: "/mnt/storage01/b01pbs01"
    content: ["backup"]
- name: Add NFS storage to Proxmox VE Cluster
  community.proxmox.proxmox_storage:
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    validate_certs: false
    nodes: ["de-cgn01-virt01", "de-cgn01-virt02"]
    state: present
    name: net-nfsshare01
    type: nfs
    nfs_options:
      server: 10.10.10.94
      export: "/mnt/storage01/s01nfs01"
    content: ["rootdir", "images"]
- name: Add iSCSI storage to Proxmox VE Cluster
  community.proxmox.proxmox_storage:
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    validate_certs: false
    nodes: ["de-cgn01-virt01", "de-cgn01-virt02", "de-cgn01-virt03"]
    state: present
    type: iscsi
    name: net-iscsi01
    iscsi_options:
      portal: 10.10.10.94
      target: "iqn.2005-10.org.freenas.ctl:s01-isci01"
    content: ["rootdir", "images"]
- name: Remove storage from Proxmox VE Cluster
  community.proxmox.proxmox_storage:
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    validate_certs: false
    state: absent
    name: net-nfsshare01
    type: nfs
"""

RETURN = r"""
storage:
  description: Status message about the storage action.
  returned: success
  type: str
  sample: "Storage 'net-nfsshare01' created successfully."
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    proxmox_auth_argument_spec, ProxmoxAnsible)


class ProxmoxNodeAnsible(ProxmoxAnsible):
    def add_storage(self):
        changed = False
        result = "Unchanged"
        storage_name = self.module.params['name']
        storage_type = self.module.params['type']
        nodes = self.module.params['nodes']
        content = self.module.params.get('content')

        # Create payload for storage creation
        payload = {
            'storage': storage_name,
            'type': storage_type,
            'nodes': nodes,
            'content': content
        }

        # Validate required parameters based on storage type
        if storage_type == "cephfs":
            cephfs_options = self.module.params.get(f'{storage_type}_options', {})
            monhost = cephfs_options.get('monhost', '')
            username = cephfs_options.get('username')
            password = cephfs_options.get('password')
            path = cephfs_options.get('path', '/')
            subdir = cephfs_options.get('subdir', None)
            client_keyring = cephfs_options.get('client_keyring')
            fs_name = cephfs_options.get('fs_name')

            if not monhost == "":
                payload['monhost'] = monhost
            if username:
                payload['username'] = username
            if password:
                payload['password'] = password
            payload['path'] = path
            payload['subdir'] = subdir
            if client_keyring:
                payload['client_keyring'] = client_keyring
            if fs_name:
                payload['fs_name'] = fs_name

        if storage_type == "cifs":
            cifs_options = self.module.params.get(f'{storage_type}_options', {})
            server = cifs_options.get('server')
            share = cifs_options.get('share')
            if not all([server, share]):
                self.module.fail_json(msg="CIFS storage requires 'server' and 'share' parameters.")
            else:
                payload['server'] = server
                payload['share'] = share

        if storage_type == "dir":
            dir_options = self.module.params.get(f'{storage_type}_options', {})
            path = dir_options.get('path')
            if not all([path]):
                self.module.fail_json(msg="Directory storage requires 'path' parameter.")
            else:
                payload['path'] = path

        if storage_type == "iscsi":
            iscsi_options = self.module.params.get(f'{storage_type}_options', {})
            portal = iscsi_options.get('portal')
            target = iscsi_options.get('target')
            if not all([portal, target]):
                self.module.fail_json(msg="iSCSI storage requires 'portal' and 'target' parameters.")
            else:
                payload['portal'] = portal
                payload['target'] = target

        if storage_type == "nfs":
            nfs_options = self.module.params.get(f'{storage_type}_options', {})
            server = nfs_options.get('server')
            export = nfs_options.get('export')
            if not all([server, export]):
                self.module.fail_json(msg="NFS storage requires 'server' and 'export' parameters.")
            else:
                payload['server'] = server
                payload['export'] = export

        if storage_type == "pbs":
            pbs_options = self.module.params.get(f'{storage_type}_options', {})
            server = pbs_options.get('server')
            username = pbs_options.get('username')
            password = pbs_options.get('password')
            datastore = pbs_options.get('datastore')
            fingerprint = pbs_options.get('fingerprint')
            if not all([server, datastore, username, password]):
                self.module.fail_json(msg="PBS storage requires 'server', 'username', 'password' and 'datastore' parameters.")
            else:
                payload['server'] = server
                payload['username'] = username
                payload['password'] = password
                payload['datastore'] = datastore
                if fingerprint:
                    payload['fingerprint'] = fingerprint

        if storage_type == "zfspool":
            zfspool_options = self.module.params.get(f'{storage_type}_options', {})
            pool = zfspool_options.get('pool')
            if not all([pool]):
                self.module.fail_json(msg="ZFS storage requires 'pool' parameter.")
            else:
                payload['pool'] = pool

        # Check Mode validation
        if self.module.check_mode:
            try:
                existing_storages = self.proxmox_api.storage.get()
            except Exception as e:
                self.module.fail_json(msg=f"Failed to retrieve storage list: {e}")

            for storage in existing_storages:
                if storage.get("storage") == storage_name:
                    changed = False
                    function_result = f"Storage '{storage_name}' already present."
                    result = {"changed": changed, "msg": function_result}
                    self.module.exit_json(**result)

                changed = True
                function_result = f"Storage '{storage_name}' would be created."
                result = {"changed": changed, "msg": function_result}
                self.module.exit_json(**result)

        # Add storage
        try:
            self.proxmox_api.storage.post(**payload)
            changed = True
            result = f"Storage '{storage_name}' created successfully."
        except Exception as e:
            error_msg = str(e)
            if "already defined" in error_msg:
                changed = False
                result = f"Storage '{storage_name}' already present."
            else:
                self.module.fail_json(msg=f"Failed to create storage: {error_msg}")

        return changed, result

    def remove_storage(self):
        changed = False
        result = "Unchanged"
        storage_name = self.module.params["name"]

        # Check Mode validation
        if self.module.check_mode:
            try:
                existing_storages = self.proxmox_api.storage.get()
            except Exception as e:
                self.module.fail_json(msg=f"Failed to retrieve storage list: {e}")

            for storage in existing_storages:
                if storage.get("storage") == storage_name:
                    changed = True
                    result = {"changed": changed, "msg": f"Storage '{storage_name}' would be deleted."}
                    self.module.exit_json(**result)

            changed = False
            result = {"changed": changed, "msg": f"Storage '{storage_name}' does not exist."}
            self.module.exit_json(**result)

        # Remove storage
        try:
            existing_storages = self.proxmox_api.storage.get()
            if not any(s.get("storage") == storage_name for s in existing_storages):
                changed = False
                result = f"Storage '{storage_name}' does not exist."
                return changed, result

            self.proxmox_api.storage(storage_name).delete()
            changed = True
            result = f"Storage '{storage_name}' removed successfully."

        except Exception as e:
            self.module.fail_json(msg=f"Failed to delete storage '{storage_name}': {e}")

        return changed, result


def main():
    module_args = proxmox_auth_argument_spec()

    storage_args = dict(
        nodes=dict(type='list', elements='str',),
        name=dict(type='str', required=True),
        state=dict(choices=['present', 'absent']),
        type=dict(choices=['cephfs', 'cifs', 'dir', 'iscsi', 'nfs', 'pbs', 'zfspool'], required=True),
        dir_options=dict(type='dict', options={
            'path': dict(type='str')
        }),
        cephfs_options=dict(type='dict', options={
            'monhost': dict(type='list', elements='str'),
            'username': dict(type='str'),
            'password': dict(type='str', no_log=True),
            'path': dict(type='str', default='/'),
            'subdir': dict(type='str',),
            'fs_name': dict(type='str',),
            'client_keyring': dict(type='str', no_log=True)
        }),
        cifs_options=dict(type='dict', options={
            'server': dict(type='str'),
            'username': dict(type='str'),
            'password': dict(type='str', no_log=True),
            'share': dict(type='str'),
            'domain': dict(type='str'),
            'smb_version': dict(type='str')
        }),
        nfs_options=dict(type='dict', options={
            'server': dict(type='str'),
            'export': dict(type='str'),
            'options': dict(type='str')
        }),
        iscsi_options=dict(type='dict', options={
            'portal': dict(type='str'),
            'target': dict(type='str')
        }),
        pbs_options=dict(type='dict', options={
            'server': dict(type='str'),
            'username': dict(type='str'),
            'password': dict(type='str', no_log=True),
            'datastore': dict(type='str'),
            'fingerprint': dict(type='str')
        }),
        zfspool_options=dict(type='dict', options={
            'pool': dict(type='str')
        }),
        content=dict(type='list', elements='str', choices=["images", "snippets", "import", "iso", "backup", "rootdir", "vztmpl"]),
    )

    module_args.update(storage_args)

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[('api_password', 'api_token_id')],
        required_together=[('api_token_id', 'api_token_secret')],
        supports_check_mode=True,
        required_if=[['state', 'present', ['nodes', 'content']]],
    )

    # Initialize objects and avoid re-polling the current
    # nodes in the cluster in each function call.
    proxmox = ProxmoxNodeAnsible(module)
    result = {"changed": False, "result": ""}

    # Actions
    if module.params.get("state") == "present":
        changed, function_result = proxmox.add_storage()
        result = {"changed": changed, "msg": function_result}

    if module.params.get("state") == "absent":
        changed, function_result = proxmox.remove_storage()
        result = {"changed": changed, "msg": function_result}

    module.exit_json(**result)


if __name__ == '__main__':
    main()
