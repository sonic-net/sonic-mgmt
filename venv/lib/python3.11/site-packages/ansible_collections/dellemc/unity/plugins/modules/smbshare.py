#!/usr/bin/python
# Copyright: (c) 2020-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: smbshare
version_added: '1.1.0'
short_description: Manage SMB shares on Unity storage system
extends_documentation_fragment:
- dellemc.unity.unity
author:
- P Srinivas Rao (@srinivas-rao5) <ansible.team@dell.com>
description:
- Managing SMB Shares on Unity storage system includes create, get,
  modify, and delete the smb shares.
options:
  share_name:
    description:
    - Name of the SMB share.
    - Required during creation of the SMB share.
    - For all other operations either I(share_name) or I(share_id) is required.
    type: str
  share_id:
    description:
    - ID of the SMB share.
    - Should not be specified during creation. Id is auto generated.
    - For all other operations either I(share_name) or I(share_id) is required.
    - If I(share_id) is used then no need to pass nas_server/filesystem/snapshot/path.
    type: str
  path:
    description:
    - Local path to the file system/Snapshot or any existing sub-folder of
      the file system/Snapshot that is shared over the network.
    - Path is relative to the root of the filesystem.
    - Required for creation of the SMB share.
    type: str
  filesystem_id:
    description:
    - The ID of the File System.
    - Either I(filesystem_name) or I(filesystem_id) is required for creation of the SMB share for filesystem.
    - If I(filesystem_name) is specified, then I(nas_server_name)/I(nas_server_id) is required to
      uniquely identify the filesystem.
    - Options I(filesystem_name) and I(filesystem_id) are mutually exclusive parameters.
    type: str
  snapshot_id:
    description:
    - The ID of the Filesystem Snapshot.
    - Either I(snapshot_name) or I(snapshot_id) is required for creation of the SMB share for a snapshot.
    - If I(snapshot_name) is specified, then I(nas_server_name)/I(nas_server_id) is required to
      uniquely identify the snapshot.
    - Options I(snapshot_name) and I(snapshot_id) are mutually exclusive parameters.
    type: str
  nas_server_id:
    description:
    - The ID of the NAS Server.
    - It is not required if I(share_id) is used.
    type: str
  filesystem_name:
    description:
    - The Name of the File System.
    - Either I(filesystem_name) or I(filesystem_id) is required for creation of the SMB share for filesystem.
    - If I(filesystem_name) is specified, then I(nas_server_name)/I(nas_server_id) is required to
      uniquely identify the filesystem.
    - Options I(filesystem_name) and I(filesytem_id) are mutually exclusive parameters.
    type: str
  snapshot_name:
    description:
    - The Name of the Filesystem Snapshot.
    - Either I(snapshot_name) or I(snapshot_id) is required for creation of the SMB share for a snapshot.
    - If I(snapshot_name) is specified, then I(nas_server_name)/I(nas_server_id) is required to
      uniquely identify the snapshot.
    - Options I(snapshot_name) and I(snapshot_id) are mutually exclusive parameters.
    type: str
  nas_server_name:
    description:
    - The Name of the NAS Server.
    - It is not required if I(share_id) is used.
    - Options I(nas_server_name) and I(nas_server_id) are mutually exclusive parameters.
    type: str
  description:
    description:
    - Description for the SMB share.
    - Optional parameter when creating a share.
    - To modify, pass the new value in description field.
    type: str
  is_abe_enabled:
    description:
    - Indicates whether Access-based Enumeration (ABE) for SMB share is enabled.
    - During creation, if not mentioned then default is C(false).
    type: bool
  is_branch_cache_enabled:
    description:
    - Indicates whether Branch Cache optimization for SMB share is enabled.
    - During creation, if not mentioned then default is C(false).
    type: bool
  is_continuous_availability_enabled:
    description:
    - Indicates whether continuous availability for SMB 3.0 is enabled.
    - During creation, if not mentioned then default is C(false).
    type: bool
  is_encryption_enabled:
    description:
    - Indicates whether encryption for SMB 3.0 is enabled at the shared folder level.
    - During creation, if not mentioned then default is C(false).
    type: bool
  offline_availability:
    description:
    - Defines valid states of Offline Availability.
    - C(MANUAL)- Only specified files will be available offline.
    - C(DOCUMENTS)- All files that users open will be available offline.
    - C(PROGRAMS)- Program will preferably run from the offline cache even when
      connected to the network. All files that users open will be available offline.
    - C(NONE)- Prevents clients from storing documents and programs in offline cache.
    type: str
    choices: ["MANUAL","DOCUMENTS","PROGRAMS","NONE"]
  umask:
    description:
    - The default UNIX umask for new files created on the SMB Share.
    type: str
  state:
    description:
    - Define whether the SMB share should exist or not.
    - Value C(present) indicates that the share should exist on the system.
    - Value C(absent) indicates that the share should not exist on the system.
    type: str
    required: true
    choices: ['absent', 'present']
notes:
- When ID/Name of the filesystem/snapshot is passed then I(nas_server) is not required.
  If passed, then filesystem/snapshot should exist for the mentioned I(nas_server),
  else the task will fail.
- The I(check_mode) is not supported.
'''

EXAMPLES = r'''
- name: Create SMB share for a filesystem
  smbshare:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    share_name: "sample_smb_share"
    filesystem_name: "sample_fs"
    nas_server_id: "NAS_11"
    path: "/sample_fs"
    description: "Sample SMB share created"
    is_abe_enabled: true
    is_branch_cache_enabled: true
    offline_availability: "DOCUMENTS"
    is_continuous_availability_enabled: true
    is_encryption_enabled: true
    umask: "777"
    state: "present"
- name: Modify Attributes of SMB share for a filesystem
  smbshare:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    share_name: "sample_smb_share"
    nas_server_name: "sample_nas_server"
    description: "Sample SMB share attributes updated"
    is_abe_enabled: false
    is_branch_cache_enabled: false
    offline_availability: "MANUAL"
    is_continuous_availability_enabled: "false"
    is_encryption_enabled: "false"
    umask: "022"
    state: "present"
- name: Create SMB share for a snapshot
  smbshare:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    share_name: "sample_snap_smb_share"
    snapshot_name: "sample_snapshot"
    nas_server_id: "NAS_11"
    path: "/sample_snapshot"
    description: "Sample SMB share created for snapshot"
    is_abe_enabled: true
    is_branch_cache_enabled: true
    is_continuous_availability_enabled: true
    is_encryption_enabled: true
    umask: "777"
    state: "present"
- name: Modify Attributes of SMB share for a snapshot
  smbshare:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    share_name: "sample_snap_smb_share"
    snapshot_name: "sample_snapshot"
    description: "Sample SMB share attributes updated for snapshot"
    is_abe_enabled: false
    is_branch_cache_enabled: false
    offline_availability: "MANUAL"
    is_continuous_availability_enabled: "false"
    is_encryption_enabled: "false"
    umask: "022"
    state: "present"
- name: Get details of SMB share
  smbshare:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    share_id: "{{smb_share_id}}"
    state: "present"
- name: Delete SMB share
  smbshare:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    share_id: "{{smb_share_id}}"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true
smb_share_details:
    description: The SMB share details.
    type: dict
    returned: When share exists.
    contains:
        id:
            description: The ID of the SMB share.
            type: str
        name:
            description: Name of the SMB share.
            type: str
            sample: "sample_smb_share"
        filesystem_id:
            description: The ID of the Filesystem.
            type: str
        filesystem_name:
            description: The Name of the filesystem
            type: str
        snapshot_id:
            description: The ID of the Snapshot.
            type: str
        snapshot_name:
            description: The Name of the Snapshot.
            type: str
        nas_server_id:
            description: The ID of the nas_server.
            type: str
        nas_server_name:
            description: The Name of the nas_server.
            type: str
        description:
            description: Additional information about the share.
            type: str
            sample: This share is created for demo purpose only.
        is_abe_enabled:
            description: Whether Access Based enumeration is enforced or not.
            type: bool
            sample: false
        is_branch_cache_enabled:
            description: Whether branch cache is enabled or not.
            type: bool
            sample: false
        is_continuous_availability_enabled:
            description: Whether the share will be available continuously or not.
            type: bool
            sample: false
        is_encryption_enabled:
            description: Whether encryption is enabled or not.
            type: bool
            sample: false
        umask:
            description: Unix mask for the SMB share.
            type: str
    sample: {
        "creation_time": "2022-03-17 11:56:54.867000+00:00",
        "description": "",
        "existed": true,
        "export_paths": [
            "\\\\multi-prot-pie.extreme1.com\\multi-prot-hui",
            "\\\\10.230.24.26\\multi-prot-hui"
        ],
        "filesystem": {
            "UnityFileSystem": {
                "hash": 8748426746492
            }
        },
        "filesystem_id": "fs_140",
        "filesystem_name": "multi-prot-hui",
        "hash": 8748426746588,
        "id": "SMBShare_20",
        "is_abe_enabled": false,
        "is_ace_enabled": false,
        "is_branch_cache_enabled": false,
        "is_continuous_availability_enabled": false,
        "is_dfs_enabled": false,
        "is_encryption_enabled": false,
        "is_read_only": null,
        "modified_time": "2022-03-17 11:56:54.867000+00:00",
        "name": "multi-prot-hui",
        "nas_server_id": "nas_5",
        "nas_server_name": "multi-prot",
        "offline_availability": "CifsShareOfflineAvailabilityEnum.NONE",
        "path": "/",
        "snap": null,
        "type": "CIFSTypeEnum.CIFS_SHARE",
        "umask": "022"
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('smbshare')

application_type = "Ansible/1.7.1"


class SMBShare(object):
    """Class with SMB Share operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_smb_share_parameters())

        # initialize the ansible module
        mut_ex_args = [['share_name', 'share_id'],
                       ['nas_server_name', 'nas_server_id'],
                       ['filesystem_name', 'snapshot_name',
                        'filesystem_id', 'snapshot_id'],
                       ['share_id', 'nas_server_name'],
                       ['share_id', 'nas_server_id'],
                       ['share_id', 'filesystem_name'],
                       ['share_id', 'filesystem_id'],
                       ['share_id', 'path'],
                       ['share_id', 'snapshot_name'],
                       ['share_id', 'snapshot_id']]
        required_one_of = [['share_id', 'share_name']]

        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=False,
            mutually_exclusive=mut_ex_args,
            required_one_of=required_one_of
        )
        utils.ensure_required_libs(self.module)

        # result is a dictionary that contains changed status and
        # snapshot details
        self.result = {"changed": False,
                       'smb_share_details': {}}

        self.unity_conn = utils.get_unity_unisphere_connection(
            self.module.params, application_type)
        self.smb_share_conn_obj = utils.cifs_share.UnityCifsShare(
            self.unity_conn)
        LOG.info('Connection established with the Unity Array')

    def get_offline_availability_enum(self, offline_availability):
        """
        Get the enum of the Offline Availability parameter.
        :param offline_availability: The offline_availability string
        :return: offline_availability enum
        """
        if offline_availability in \
                utils.CifsShareOfflineAvailabilityEnum.__members__:
            return utils.CifsShareOfflineAvailabilityEnum[
                offline_availability]
        else:
            error_msg = "Invalid value {0} for offline availability" \
                        " provided".format(offline_availability)
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_smb_share_obj(self, share_id=None, share_name=None,
                          filesystem_obj=None, snap_obj=None, nas_obj=None):
        """Get SMB share details"""
        msg = "Failed to get details of SMB Share {0} with error {1} "
        smb_share = share_name if share_name else share_id
        try:
            if share_id:
                obj_smb = self.unity_conn.get_cifs_share(_id=share_id)
                if obj_smb and obj_smb.existed:
                    LOG.info("Successfully got the SMB share "
                             "object %s ", obj_smb)
                    return obj_smb

            elif share_name is not None and filesystem_obj:
                # There might be a case where SMB share with same name exists
                # for different nas server. Hence, filesystem_obj is passed
                # along with share name to get a unique resource.
                return self.unity_conn.get_cifs_share(
                    name=share_name, filesystem=filesystem_obj)

            elif share_name is not None and snap_obj:
                # There might be a case where SMB share with same name exists
                # for different nas server. Hence, snap_obj is passed
                # along with share name to get a unique resource.
                return self.unity_conn.get_cifs_share(
                    name=share_name, snap=snap_obj)

            # This elif is addressing scenario where nas server details is
            # passed and neither filesystem nor snapshot details are passed.
            elif share_name is not None and nas_obj:
                # Multiple smb shares can be received, as only name is passed
                smb_share_obj = self.unity_conn.get_cifs_share(
                    name=share_name)

                # Checking if instance or list of instance is returned.
                if isinstance(smb_share_obj,
                              utils.cifs_share.UnityCifsShareList):
                    LOG.info("Multiple SMB share with same name found.")
                    smb_share_obj_list = smb_share_obj

                    for smb_share in smb_share_obj_list:
                        if smb_share.filesystem.nas_server == nas_obj:
                            return smb_share

                    msg = "No SMB share found with the given NAS Server." \
                          " Please provide correct share name and" \
                          " nas server details."
                    return None

                # Below statements will execute when there is only single
                # smb share returned.
                if smb_share_obj.filesystem.nas_server == nas_obj:
                    return smb_share_obj
                msg = "No SMB share found with the given NAS Server." \
                      " Please provide correct share name and" \
                      " nas server details."
                return None

            else:
                self.module.fail_json(
                    msg="Share Name is Passed. Please enter Filesystem/"
                        "Snapshot/NAS Server Resource along with share_name"
                        " to get the details of the SMB share")

        except utils.HttpError as e:
            if e.http_status == 401:
                cred_err = "Incorrect username or password , {0}".format(
                    e.message)
                self.module.fail_json(msg=cred_err)
            else:
                err_msg = msg.format(smb_share, str(e))
                LOG.error(err_msg)
                self.module.fail_json(msg=err_msg)

        except utils.UnityResourceNotFoundError as e:
            err_msg = msg.format(smb_share, str(e))
            LOG.error(err_msg)
            return None

        except Exception as e:
            err_msg = msg.format(smb_share, str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def create_smb_share(self, share_name, path, filesystem_obj=None,
                         snapshot_obj=None, description=None,
                         is_abe_enabled=None, is_branch_cache_enabled=None,
                         is_continuous_availability_enabled=None,
                         is_encryption_enabled=None,
                         offline_availability=None, umask=None):
        """
        Create SMB Share
        :return: SMB Share Object if successful, else error.
        """
        if path is None or path == "":
            self.module.fail_json(msg="Please enter a valid path."
                                      " Empty string or None provided.")
        if not filesystem_obj and not snapshot_obj:
            self.module.fail_json(msg="Either Filesystem or Snapshot "
                                      "Resource's Name/ID is required to"
                                      " Create a SMB share")
        try:
            if filesystem_obj:
                return self.smb_share_conn_obj.create(
                    cli=self.unity_conn._cli, name=share_name,
                    fs=filesystem_obj, path=path,
                    is_encryption_enabled=is_encryption_enabled,
                    is_con_avail_enabled=is_continuous_availability_enabled,
                    is_abe_enabled=is_abe_enabled,
                    is_branch_cache_enabled=is_branch_cache_enabled,
                    umask=umask, description=description,
                    offline_availability=offline_availability)
            else:
                return self.smb_share_conn_obj.create_from_snap(
                    cli=self.unity_conn._cli, name=share_name,
                    snap=snapshot_obj, path=path,
                    is_encryption_enabled=is_encryption_enabled,
                    is_con_avail_enabled=is_continuous_availability_enabled,
                    is_abe_enabled=is_abe_enabled,
                    is_branch_cache_enabled=is_branch_cache_enabled,
                    umask=umask, description=description,
                    offline_availability=offline_availability)

        except Exception as e:
            error_msg = "Failed to create SMB share" \
                        " %s with error %s" % (share_name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_filesystem(self, filesystem_id=None, filesystem_name=None,
                       nas_server_obj=None):
        """
        Get the Filesystem Object.
        :param filesystem_id: ID of the Filesystem.
        :param filesystem_name: Name of the filesystem.
        :param nas_server_obj: NAS Server object.
        :return: Object of the filesystem.
        """
        try:
            if filesystem_id:
                obj_fs = self.unity_conn.get_filesystem(_id=filesystem_id)
                if obj_fs and obj_fs.existed:
                    LOG.info("Successfully got the filesystem "
                             "object %s ", obj_fs)
                    return obj_fs
            else:
                return self.unity_conn.get_filesystem(
                    name=filesystem_name, nas_server=nas_server_obj)
            return None
        except Exception as e:
            filesystem = filesystem_name if filesystem_name \
                else filesystem_id
            err_msg = "Failed to get filesystem details {0} with" \
                      " error {1}".format(filesystem, str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def get_snapshot(self, snapshot_name, snapshot_id):
        """
        Get the Snapshot Object.
        :param snapshot_id: ID of the Snapshot.
        :param snapshot_name: Name of the Snapshot
        :return: Object of the filesystem.
        """
        try:
            obj_snap = self.unity_conn.get_snap(_id=snapshot_id,
                                                name=snapshot_name)
            if snapshot_id and obj_snap and not obj_snap.existed:
                LOG.info("Snapshot object does not exist %s ", obj_snap)
                return None
            return obj_snap
        except Exception as e:
            snapshot = snapshot_name if snapshot_name else snapshot_id
            err_msg = "Failed to get filesystem snapshots details {0} with" \
                      " error {1}".format(snapshot, str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def get_nas_server(self, nas_server_name, nas_server_id):
        """
        Get the NAS Server Object using NAME/ID of the NAS Server.
        :param nas_server_name: Name of the NAS Server
        :param nas_server_id: ID of the NAS Server
        :return: NAS Server object.
        """
        nas_server = nas_server_name if nas_server_name else nas_server_id
        try:
            obj_nas = self.unity_conn.get_nas_server(_id=nas_server_id,
                                                     name=nas_server_name)
            if nas_server_id and obj_nas and not obj_nas.existed:
                LOG.info("NAS Server object does not exist %s ", obj_nas)
                return None
            return obj_nas
        except utils.HttpError as e:
            if e.http_status == 401:
                cred_err = "Incorrect username or password , {0}".format(
                    e.message)
                self.module.fail_json(msg=cred_err)
            else:
                err_msg = "Failed to get details of NAS Server" \
                          " {0} with error {1}".format(nas_server, str(e))
                LOG.error(err_msg)
                self.module.fail_json(msg=err_msg)
        except Exception as e:
            nas_server = nas_server_name if nas_server_name \
                else nas_server_id
            err_msg = "Failed to get nas server details {0} with" \
                      " error {1}".format(nas_server, str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def delete_smb_share(self, smb_share_obj):
        """
        Delete SMB share if exists, else thrown error.
        """
        try:
            smb_share_obj.delete()
        except Exception as e:
            error_msg = "Failed to Delete SMB share" \
                        " %s with error %s" % (smb_share_obj.name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def to_update(self, smb_share_obj):
        LOG.info("Checking Whether the parameters are modified or not.")

        offline_availability = self.module.params['offline_availability']
        # Get the enum for the corresponding offline_availability
        if offline_availability:
            offline_availability = \
                self.get_offline_availability_enum(offline_availability)
        if offline_availability is not None and \
                offline_availability != smb_share_obj.offline_availability:
            return True

        smb_share_dict = smb_share_obj._get_properties()
        params_list = ['is_abe_enabled', 'is_branch_cache_enabled',
                       'is_continuous_availability_enabled',
                       'is_encryption_enabled', 'description', 'umask']
        for param in params_list:
            if self.module.params[param] is not None and \
                    self.module.params[param] != smb_share_dict[param]:
                return True
        return False

    def update_smb_share(self, smb_share_obj, is_encryption_enabled=None,
                         is_continuous_availability_enabled=None,
                         is_abe_enabled=None,
                         is_branch_cache_enabled=None,
                         umask=None, description=None,
                         offline_availability=None):
        """
        The Details of the SMB share will be updated in the function.
        """
        try:
            smb_share_obj.modify(
                is_encryption_enabled=is_encryption_enabled,
                is_con_avail_enabled=is_continuous_availability_enabled,
                is_abe_enabled=is_abe_enabled,
                is_branch_cache_enabled=is_branch_cache_enabled,
                umask=umask, description=description,
                offline_availability=offline_availability)

        except Exception as e:
            error_msg = "Failed to Update parameters of SMB share" \
                        " %s with error %s" % (smb_share_obj.name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def perform_module_operation(self):
        """
        Perform different actions on SMB share based on user parameters
        chosen in playbook
        """
        state = self.module.params['state']
        share_name = self.module.params['share_name']
        filesystem_name = self.module.params['filesystem_name']
        snapshot_name = self.module.params['snapshot_name']
        nas_server_name = self.module.params['nas_server_name']
        share_id = self.module.params['share_id']
        filesystem_id = self.module.params['filesystem_id']
        snapshot_id = self.module.params['snapshot_id']
        nas_server_id = self.module.params['nas_server_id']
        path = self.module.params['path']

        description = self.module.params['description']
        is_branch_cache_enabled = \
            self.module.params['is_branch_cache_enabled']
        is_continuous_availability_enabled = \
            self.module.params['is_continuous_availability_enabled']
        is_encryption_enabled = self.module.params['is_encryption_enabled']
        is_abe_enabled = self.module.params['is_abe_enabled']
        umask = self.module.params['umask']

        offline_availability = self.module.params['offline_availability']
        # Get the enum for the corresponding offline_availability
        if offline_availability:
            offline_availability = \
                self.get_offline_availability_enum(offline_availability)

        changed = False
        '''
        Validate parameters.
        '''
        if share_id is not None and \
                (share_id == "" or len(share_id.split()) == 0):
            self.module.fail_json(msg="Invalid share id provided."
                                      " Please enter a valid share ID.")

        '''
        Get details of NAS Server, if entered.
        '''
        nas_server_obj = None
        if nas_server_name or nas_server_id:
            nas_server_obj = self.get_nas_server(nas_server_name,
                                                 nas_server_id)
        if nas_server_obj:
            msg = "NAS Server Object:" \
                  " {0}".format(nas_server_obj._get_properties())
            LOG.info(msg)
        else:
            msg = "NAS Server Resource not fetched."
            LOG.info(msg)

        '''
        Get details of Filesystem, if entered.
        '''
        filesystem_obj = None
        if filesystem_id:
            filesystem_obj = self.get_filesystem(filesystem_id)
        if filesystem_name:
            # nas_server_obj is required to uniquely identify filesystem
            # resource. If neither nas_server_name nor nas_server_id
            # is passed along with filesystem_name then error is thrown.
            if not nas_server_obj:
                self.module.fail_json(msg="nas_server_id/nas_server_name is "
                                          "required when filesystem_name is "
                                          "passed")
            filesystem_obj = self.get_filesystem(
                None, filesystem_name, nas_server_obj)
        if filesystem_obj:
            msg = "Filesystem Object:" \
                  " {0}".format(filesystem_obj._get_properties())
            LOG.info(msg)
        # Checking if filesystem supports SMB protocol or not.
        if filesystem_obj and \
                filesystem_obj.supported_protocols.name == "NFS":
            self.module.fail_json(msg="Cannot perform SMB share operations "
                                      "as file system supports only NFS "
                                      "protocol. Please enter a valid "
                                      "Filesystem having supported protocol"
                                      " as SMB or Multiprotocol.")
        '''
        Get details of Snapshot, if entered.
        '''
        snapshot_obj = None
        if snapshot_id or snapshot_name:
            # Snapshot Name and Snapshot ID both are unique across array.
            # Hence no need to mention nas server details
            snapshot_obj = self.get_snapshot(snapshot_name, snapshot_id)
        if snapshot_obj:
            msg = "Snapshot Object:" \
                  " {0}".format(snapshot_obj._get_properties())
            LOG.info(msg)
        else:
            msg = "Snapshot Resource not fetched."
            LOG.info(msg)

        '''
        Get the Details of the SMB Share
        '''
        smb_share_obj = self.get_smb_share_obj(
            share_id, share_name, filesystem_obj, snapshot_obj,
            nas_server_obj)
        if smb_share_obj:
            msg = "SMB Share Object:" \
                  " {0}".format(smb_share_obj._get_properties())
            LOG.info(msg)
        elif state == 'present' and share_id:
            msg = "Unable to fetch SMB Share Resource. " \
                  "Incorrect SMB share id provided. " \
                  "Please enter a correct share id."
            LOG.error(msg)
            self.module.fail_json(msg=msg)

        '''
        Creation of SMB Share
        '''
        if state == "present" and not smb_share_obj:
            smb_share_obj = self.create_smb_share(
                share_name, path, filesystem_obj, snapshot_obj, description,
                is_abe_enabled, is_branch_cache_enabled,
                is_continuous_availability_enabled, is_encryption_enabled,
                offline_availability, umask)
            changed = True

        '''
        Update the SMB share details
        '''
        if state == "present" and smb_share_obj:
            LOG.info("Modify the details of the SMB share.")
            update_flag = self.to_update(smb_share_obj)
            msg = "Update Flag: {0}".format(str(update_flag))
            LOG.info(msg)
            if update_flag:
                self.update_smb_share(smb_share_obj, is_encryption_enabled,
                                      is_continuous_availability_enabled,
                                      is_abe_enabled,
                                      is_branch_cache_enabled,
                                      umask, description,
                                      offline_availability)
                changed = True

        '''
        Delete the SMB share details
        '''
        if state == "absent" and smb_share_obj:
            self.delete_smb_share(smb_share_obj)
            changed = True

        '''
        Update the changed state and SMB share details
        '''

        self.result["changed"] = changed
        smb_details = self.prepare_output_dict(state, share_id, share_name,
                                               filesystem_obj, snapshot_obj,
                                               nas_server_obj)
        self.result["smb_share_details"] = smb_details
        self.module.exit_json(**self.result)

    def prepare_output_dict(self, state, share_id, share_name,
                            filesystem_obj, snapshot_obj, nas_server_obj):
        smb_share_details = None
        smb_share_obj = None
        if state == 'present':
            smb_share_obj = self.get_smb_share_obj(
                share_id, share_name, filesystem_obj,
                snapshot_obj, nas_server_obj)
            smb_share_details = smb_share_obj._get_properties()
        if smb_share_details:
            # Get Snapshot NAME and ID if SMB share exists for Snapshot
            if smb_share_obj.type.name == "CIFS_SNAPSHOT":
                smb_share_details['snapshot_name'] = smb_share_obj.snap.name
                smb_share_details['snapshot_id'] = smb_share_obj.snap.id

            # Get Filesystem NAME and ID
            smb_share_details['filesystem_name'] = \
                smb_share_obj.filesystem.name
            smb_share_details['filesystem_id'] = smb_share_obj.filesystem.id

            # Get NAS server NAME and ID
            smb_share_details['nas_server_name'] = \
                smb_share_obj.filesystem.nas_server.name
            smb_share_details['nas_server_id'] = \
                smb_share_obj.filesystem.nas_server.id
        return smb_share_details


def get_smb_share_parameters():
    """
    This method provides parameters required for the ansible smb share
    modules on Unity
    """

    return dict(
        share_name=dict(), share_id=dict(),
        filesystem_name=dict(), filesystem_id=dict(),
        snapshot_name=dict(), snapshot_id=dict(),
        nas_server_name=dict(), nas_server_id=dict(),
        path=dict(no_log=True), umask=dict(), description=dict(),
        offline_availability=dict(
            choices=["MANUAL", "DOCUMENTS", "PROGRAMS", "NONE"]),
        is_abe_enabled=dict(type='bool'),
        is_branch_cache_enabled=dict(type='bool'),
        is_continuous_availability_enabled=dict(type='bool'),
        is_encryption_enabled=dict(type='bool'),
        state=dict(required=True, choices=['present', 'absent'], type='str')
    )


def main():
    """ Create Unity SMB share object and perform action on it
        based on user input from playbook"""
    obj = SMBShare()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
