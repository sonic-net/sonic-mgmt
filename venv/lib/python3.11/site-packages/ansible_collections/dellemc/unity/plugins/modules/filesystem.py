#!/usr/bin/python
# Copyright: (c) 2020-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing FileSystem on Unity"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""

module: filesystem
version_added: '1.1.0'
short_description: Manage filesystem on Unity storage system
description:
- Managing filesystem on Unity storage system includes
  Create new filesystem,
  Modify snapschedule attribute of filesystem,
  Modify filesystem attributes,
  Display filesystem details,
  Display filesystem snapshots,
  Display filesystem snapschedule,
  Delete snapschedule associated with the filesystem,
  Delete filesystem,
  Create new filesystem with quota configuration,
  Enable, modify and disable replication.

extends_documentation_fragment:
  -  dellemc.unity.unity

author:
- Arindam Datta (@dattaarindam) <ansible.team@dell.com>
- Meenakshi Dembi (@dembim) <ansible.team@dell.com>
- Spandita Panigrahi (@panigs7) <ansible.team@dell.com>

options:
  filesystem_name:
    description:
    - The name of the filesystem. Mandatory only for the create operation.
      All the operations are supported through I(filesystem_name).
    - It is mutually exclusive with I(filesystem_id).
    type: str
  filesystem_id:
    description:
    - The id of the filesystem.
    - It can be used only for get, modify, or delete operations.
    - It is mutually exclusive with I(filesystem_name).
    type: str
  pool_name:
    description:
    - This is the name of the pool where the filesystem will be created.
    - Either the I(pool_name) or I(pool_id) must be provided to create a new
      filesystem.
    type: str
  pool_id:
    description:
    - This is the ID of the pool where the filesystem will be created.
    - Either the I(pool_name) or I(pool_id) must be provided to create a new
      filesystem.
    type: str
  size:
    description:
     - The size of the filesystem.
    type: int
  cap_unit:
    description:
     - The unit of the filesystem size. It defaults to C(GB), if not specified.
    choices: ['GB' , 'TB']
    type: str
  nas_server_name:
    description:
    - Name of the NAS server on which filesystem will be hosted.
    type: str
  nas_server_id:
    description:
    - ID of the NAS server on which filesystem will be hosted.
    type: str
  supported_protocols:
    description:
    - Protocols supported by the file system.
    - It will be overridden by NAS server configuration if NAS Server is C(Multiprotocol).
    type: str
    choices: ['NFS', 'CIFS', 'MULTIPROTOCOL']
  description:
    description:
    - Description about the filesystem.
    - Description can be removed by passing empty string ("").
    type: str
  smb_properties:
    description:
    - Advance settings for SMB. It contains optional candidate variables.
    type: dict
    suboptions:
      is_smb_sync_writes_enabled:
        description:
        - Indicates whether the synchronous writes option is enabled on the
          file system.
        type: bool
      is_smb_notify_on_access_enabled:
        description:
        - Indicates whether notifications of changes to directory file
          structure are enabled.
        type: bool
      is_smb_op_locks_enabled:
        description:
        - Indicates whether opportunistic file locking is enabled on the file
          system.
        type: bool
      is_smb_notify_on_write_enabled:
        description:
        - Indicates whether file write notifications are enabled on the file
          system.
        type: bool
      smb_notify_on_change_dir_depth:
        description:
        - Integer variable, determines the lowest directory level to which
          the enabled notifications apply.
        - Minimum value is C(1).
        type: int
  data_reduction:
    description:
    - Boolean variable, specifies whether or not to enable compression.
      Compression is supported only for thin filesystem.
    type: bool
  is_thin:
    description:
    - Boolean variable, specifies whether or not it is a thin filesystem.
    type: bool
  access_policy:
    description:
    - Access policy of a filesystem.
    choices: ['NATIVE', 'UNIX', 'WINDOWS']
    type: str
  locking_policy:
    description:
    - File system locking policies. These policy choices control whether the
      NFSv4 range locks must be honored.
    type: str
    choices: ['ADVISORY', 'MANDATORY']
  tiering_policy:
    description:
    - Tiering policy choices for how the storage resource data will be
      distributed among the tiers available in the pool.
    choices: ['AUTOTIER_HIGH', 'AUTOTIER', 'HIGHEST', 'LOWEST']
    type: str
  quota_config:
    description:
    - Configuration for quota management. It contains optional parameters.
    type: dict
    suboptions:
        grace_period:
            description:
            - Grace period set in quota configuration after soft limit is reached.
            - If I(grace_period) is not set during creation of filesystem,
              it will be set to C(7 days) by default.
            type: int
        grace_period_unit:
            description:
            - Unit of grace period.
            - Default unit is C(days).
            type: str
            choices: ['minutes', 'hours', 'days']
        default_hard_limit:
            description:
            - Default hard limit for user quotas and tree quotas.
            - If I(default_hard_limit) is not set while creation of filesystem,
              it will be set to C(0B) by default.
            type: int
        default_soft_limit:
            description:
            - Default soft limit for user quotas and tree quotas.
            - If I(default_soft_limit) is not set while creation of filesystem,
              it will be set to C(0B) by default.
            type: int
        is_user_quota_enabled:
            description:
            - Indicates whether the user quota is enabled.
            - If I(is_user_quota_enabled) is not set while creation of filesystem,
              it will be set to C(false) by default.
            - Parameters I(is_user_quota_enabled) and I(quota_policy) are
              mutually exclusive.
            type: bool
        quota_policy:
            description:
            - Quota policy set in quota configuration.
            - If I(quota_policy) is not set while creation of filesystem, it will
              be set to C(FILE_SIZE) by default.
            - Parameters I(is_user_quota_enabled) and I(quota_policy) are
              mutually exclusive.
            choices: ['FILE_SIZE','BLOCKS']
            type: str
        cap_unit:
            description:
            - Unit of I(default_soft_limit) and I(default_hard_limit) size.
            - Default unit is C(GB).
            choices: ['MB', 'GB', 'TB']
            type: str
  state:
    description:
    - State variable to determine whether filesystem will exist or not.
    choices: ['absent', 'present']
    required: true
    type: str
  snap_schedule_name:
    description:
    - This is the name of an existing snapshot schedule which is to be associated with the filesystem.
    - This is mutually exclusive with I(snapshot_schedule_id).
    type: str
  snap_schedule_id:
    description:
    - This is the id of an existing snapshot schedule which is to be associated with the filesystem.
    - This is mutually exclusive with I(snapshot_schedule_name).
    type: str
  replication_params:
    description:
    - Settings required for enabling or modifying replication.
    type: dict
    suboptions:
      replication_name:
        description:
        - Name of the replication session.
        type: str
      new_replication_name:
        description:
        - Replication name to rename the session to.
        type: str
      replication_mode:
        description:
        - The replication mode.
        - This is a mandatory field while creating a replication session.
        type: str
        choices: ['synchronous', 'asynchronous', 'manual']
      rpo:
        description:
        - Maximum time to wait before the system syncs the source and destination LUNs.
        - The I(rpo) option should be specified if the I(replication_mode) is C(asynchronous).
        - The value should be in range of C(5) to C(1440) for C(asynchronous),
          C(0) for C(synchronous) and C(-1) for C(manual).
        type: int
      replication_type:
        description:
        - Type of replication.
        choices: ['local', 'remote']
        type: str
      remote_system:
        description:
        - Details of remote system to which the replication is being configured.
        - The I(remote_system) option should be specified if the I(replication_type) is C(remote).
        type: dict
        suboptions:
          remote_system_host:
            required: true
            description:
            - IP or FQDN for remote Unity unisphere Host.
            type: str
          remote_system_username:
            type: str
            required: true
            description:
            - User name of remote Unity unisphere Host.
          remote_system_password:
            type: str
            required: true
            description:
            - Password of remote Unity unisphere Host.
          remote_system_verifycert:
            type: bool
            default: true
            description:
            - Boolean variable to specify whether or not to validate SSL
              certificate of remote Unity unisphere Host.
            - C(true) - Indicates that the SSL certificate should be verified.
            - C(false) - Indicates that the SSL certificate should not be
              verified.
          remote_system_port:
            description:
            - Port at which remote Unity unisphere is hosted.
            type: int
            default: 443
      destination_pool_id:
        type: str
        description:
        - ID of pool to allocate destination filesystem.
      destination_pool_name:
        type: str
        description:
        - Name of pool to allocate destination filesystem.
  replication_state:
    description:
    - State of the replication.
    choices: ['enable', 'disable']
    type: str

notes:
- SMB shares, NFS exports, and snapshots associated with filesystem need
  to be deleted prior to deleting a filesystem.
- The I(quota_config) parameter can be used to update default hard limit
  and soft limit values to limit the maximum space that can be used.
  By default they both are set to 0 during filesystem
  creation which means unlimited.
- The I(check_mode) is not supported.
"""

EXAMPLES = r"""
- name: Create FileSystem
  filesystem:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_name: "ansible_test_fs"
    nas_server_name: "lglap761"
    pool_name: "pool_1"
    size: 5
    state: "present"

- name: Create FileSystem with quota configuration
  filesystem:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_name: "ansible_test_fs"
    nas_server_name: "lglap761"
    pool_name: "pool_1"
    size: 5
    quota_config:
      grace_period: 8
      grace_period_unit: "days"
      default_soft_limit: 10
      is_user_quota_enabled: false
    state: "present"

- name: Expand FileSystem size
  filesystem:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_name: "ansible_test_fs"
    nas_server_name: "lglap761"
    size: 10
    state: "present"

- name: Expand FileSystem size
  filesystem:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_name: "ansible_test_fs"
    nas_server_name: "lglap761"
    size: 10
    state: "present"

- name: Modify FileSystem smb_properties
  filesystem:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_name: "ansible_test_fs"
    nas_server_name: "lglap761"
    smb_properties:
      is_smb_op_locks_enabled: true
      smb_notify_on_change_dir_depth: 5
      is_smb_notify_on_access_enabled: true
    state: "present"

- name: Modify FileSystem Snap Schedule
  filesystem:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "fs_141"
    snap_schedule_id: "{{snap_schedule_id}}"
    state: "{{state_present}}"

- name: Get details of FileSystem using id
  filesystem:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "rs_405"
    state: "present"

- name: Delete a FileSystem using id
  filesystem:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "rs_405"
    state: "absent"

- name: Enable replication on the fs
  filesystem:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "rs_405"
    replication_params:
      replication_name: "test_repl"
      replication_type: "remote"
      replication_mode: "asynchronous"
      rpo: 60
      remote_system:
        remote_system_host: '0.1.2.3'
        remote_system_verifycert: false
        remote_system_username: 'username'
        remote_system_password: 'password'
      destination_pool_name: "pool_test_1"
    replication_state: "enable"
    state: "present"

- name: Modify replication on the fs
  filesystem:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "rs_405"
    replication_params:
      replication_name: "test_repl"
      new_replication_name: "test_repl_updated"
      replication_mode: "asynchronous"
      rpo: 50
    replication_state: "enable"
    state: "present"

- name: Disable replication on the fs
  filesystem:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "rs_405"
    replication_state: "disable"
    state: "present"

- name: Disable replication by specifying replication_name on the fs
  filesystem:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "rs_405"
    replication_params:
      replication_name: "test_replication"
    replication_state: "disable"
    state: "present"
"""

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true

filesystem_details:
    description: Details of the filesystem.
    returned: When filesystem exists
    type: dict
    contains:
        id:
            description: The system generated ID given to the filesystem.
            type: str
        name:
            description: Name of the filesystem.
            type: str
        description:
            description: Description about the filesystem.
            type: str
        is_data_reduction_enabled:
            description: Whether or not compression enabled on this
                         filesystem.
            type: bool
        size_total_with_unit:
            description: Size of the filesystem with actual unit.
            type: str
        tiering_policy:
            description: Tiering policy applied to this filesystem.
            type: str
        is_cifs_notify_on_access_enabled:
            description: Indicates whether the system generates a
                         notification when a user accesses the file system.
            type: bool
        is_cifs_notify_on_write_enabled:
            description: Indicates whether the system generates a notification
                         when the file system is written to.
            type: bool
        is_cifs_op_locks_enabled:
            description: Indicates whether opportunistic file locks are enabled
                         for the file system.
            type: bool
        is_cifs_sync_writes_enabled:
            description: Indicates whether the CIFS synchronous writes option
                         is enabled for the file system.
            type: bool
        cifs_notify_on_change_dir_depth:
            description: Indicates the lowest directory level to which the
                         enabled notifications apply, if any.
            type: int
        pool:
            description: The pool in which this filesystem is allocated.
            type: dict
            contains:
                id:
                    description: The system ID given to the pool.
                    type: str
                name:
                    description: The name of the storage pool.
                    type: str
        nas_server:
            description: The NAS Server details on which this filesystem is hosted.
            type: dict
            contains:
                id:
                    description: The system ID given to the NAS Server.
                    type: str
                name:
                    description: The name of the NAS Server.
                    type: str
        snapshots:
            description: The list of snapshots of this filesystem.
            type: list
            contains:
                id:
                    description: The system ID given to the filesystem
                                    snapshot.
                    type: str
                name:
                    description: The name of the filesystem snapshot.
                    type: str
        is_thin_enabled:
            description: Indicates whether thin provisioning is enabled for
                         this filesystem.
            type: bool
        snap_schedule_id:
            description: Indicates the id of the snap schedule associated
                         with the filesystem.
            type: str
        snap_schedule_name:
            description: Indicates the name of the snap schedule associated
                         with the filesystem.
            type: str
        quota_config:
            description: Details of quota configuration of the filesystem
                         created.
            type: dict
            contains:
                grace_period:
                    description: Grace period set in quota configuration
                                 after soft limit is reached.
                    type: str
                default_hard_limit:
                    description: Default hard limit for user quotas
                                 and tree quotas.
                    type: int
                default_soft_limit:
                    description: Default soft limit for user quotas
                                 and tree quotas.
                    type: int
                is_user_quota_enabled:
                    description: Indicates whether the user quota is enabled.
                    type: bool
                quota_policy:
                    description: Quota policy set in quota configuration.
                    type: str
        replication_sessions:
            description: List of replication sessions if replication is enabled.
            type: dict
            contains:
                id:
                    description: ID of replication session
                    type: str
                name:
                    description: Name of replication session
                    type: str
                remote_system:
                    description: Remote system
                    type: dict
                    contains:
                        id:
                            description: ID of remote system
                            type: str
    sample: {
        "access_policy": "AccessPolicyEnum.UNIX",
        "cifs_notify_on_change_dir_depth": 512,
        "cifs_share": null,
        "data_reduction_percent": 0,
        "data_reduction_ratio": 1.0,
        "data_reduction_size_saved": 0,
        "description": "",
        "existed": true,
        "folder_rename_policy": "FSRenamePolicyEnum.SMB_RENAME_FORBIDDEN",
        "format": "FSFormatEnum.UFS64",
        "hash": 8735427610152,
        "health": {
            "UnityHealth": {
                "hash": 8735427614928
            }
        },
        "host_io_size": "HostIOSizeEnum.GENERAL_8K",
        "id": "fs_65916",
        "is_advanced_dedup_enabled": false,
        "is_cifs_notify_on_access_enabled": false,
        "is_cifs_notify_on_write_enabled": false,
        "is_cifs_op_locks_enabled": false,
        "is_cifs_sync_writes_enabled": false,
        "is_data_reduction_enabled": false,
        "is_read_only": false,
        "is_smbca": false,
        "is_thin_enabled": true,
        "locking_policy": "FSLockingPolicyEnum.MANDATORY",
        "metadata_size": 11274289152,
        "metadata_size_allocated": 4294967296,
        "min_size_allocated": 0,
        "name": "test_fs",
        "nas_server": {
            "id": "nas_18",
            "name": "test_nas1"
        },
        "nfs_share": null,
        "per_tier_size_used": [
            6979321856,
            0,
            0
        ],
        "pool": {
            "id": "pool_7",
            "name": "pool 7"
        },
        "pool_full_policy": "ResourcePoolFullPolicyEnum.FAIL_WRITES",
        "quota_config": {
            "default_hard_limit": "0B",
            "default_soft_limit": "0B",
            "grace_period": "7.0 days",
            "id": "quotaconfig_171798760421_0",
            "is_user_quota_enabled": false,
            "quota_policy": "QuotaPolicyEnum.FILE_SIZE"
        },
        "replication_sessions": {
            "current_transfer_est_remain_time": 0,
            "id": "***",
            "last_sync_time": "2022-05-12 11:20:38+00:00",
            "local_role": "ReplicationSessionReplicationRoleEnum.SOURCE",
            "max_time_out_of_sync": 60,
            "members": null,
            "name": "local_repl_new",
            "network_status": "ReplicationSessionNetworkStatusEnum.OK",
            "remote_system": {
                "UnityRemoteSystem": {
                    "hash": 8735426929707
                }
            },
            "replication_resource_type": "ReplicationEndpointResourceTypeEnum.FILESYSTEM",
            "src_resource_id": "res_66444",
            "src_status": "ReplicationSessionStatusEnum.OK",
            "status": "ReplicationOpStatusEnum.AUTO_SYNC_CONFIGURED",
            "sync_progress": 0,
            "sync_state": "ReplicationSessionSyncStateEnum.IDLE"
        },
        "size_allocated": 283148288,
        "size_allocated_total": 4578148352,
        "size_preallocated": 2401173504,
        "size_total": 10737418240,
        "size_total_with_unit": "10.0 GB",
        "size_used": 1620312064,
        "snap_count": 2,
        "snaps_size": 21474869248,
        "snaps_size_allocated": 32768,
        "snapshots": [],
        "supported_protocols": "FSSupportedProtocolEnum.NFS",
        "tiering_policy": "TieringPolicyEnum.AUTOTIER_HIGH",
        "type": "FilesystemTypeEnum.FILESYSTEM"
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('filesystem')

application_type = "Ansible/1.7.1"


class Filesystem(object):
    """Class with FileSystem operations"""

    def __init__(self):
        """Define all parameters required by this module"""
        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_filesystem_parameters())

        mutually_exclusive = [['filesystem_name', 'filesystem_id'],
                              ['pool_name', 'pool_id'],
                              ['nas_server_name', 'nas_server_id'],
                              ['snap_schedule_name', 'snap_schedule_id']]

        required_one_of = [['filesystem_name', 'filesystem_id']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=False,
            mutually_exclusive=mutually_exclusive,
            required_one_of=required_one_of)
        utils.ensure_required_libs(self.module)

        self.unity_conn = utils.get_unity_unisphere_connection(
            self.module.params, application_type)

    def get_filesystem(self, name=None, id=None, obj_nas_server=None):
        """Get the details of a FileSystem.
            :param filesystem_name: The name of the filesystem
            :param filesystem_id: The id of the filesystem
            :param obj_nas_server: NAS Server object instance
            :return: instance of the respective filesystem if exist.
        """

        id_or_name = id if id else name
        errormsg = "Failed to get the filesystem {0} with error {1}"

        try:
            obj_fs = None
            if id:
                if obj_nas_server:
                    obj_fs = self.unity_conn.get_filesystem(
                        _id=id,
                        nas_server=obj_nas_server)
                else:
                    obj_fs = self.unity_conn.get_filesystem(_id=id)

                if obj_fs and obj_fs.existed:
                    LOG.info("Successfully got the filesystem "
                             "object %s ", obj_fs)
                    return obj_fs
            elif name:
                if not obj_nas_server:
                    err_msg = "NAS Server is required to get the FileSystem"
                    LOG.error(err_msg)
                    self.module.fail_json(msg=err_msg)

                obj_fs = self.unity_conn.get_filesystem(
                    name=name,
                    nas_server=obj_nas_server)
                if obj_fs:
                    LOG.info(
                        "Successfully got the filesystem object %s ", obj_fs)
                    return obj_fs
            else:
                LOG.info("Failed to get the filesystem %s", id_or_name)
            return None

        except utils.HttpError as e:
            if e.http_status == 401:
                cred_err = "Incorrect username or password , {0}".format(
                    e.message)
                msg = errormsg.format(id_or_name, cred_err)
                self.module.fail_json(msg=msg)
            else:
                msg = errormsg.format(id_or_name, str(e))
                self.module.fail_json(msg=msg)

        except utils.UnityResourceNotFoundError as e:
            msg = errormsg.format(id_or_name, str(e))
            LOG.error(msg)
            return None

        except Exception as e:
            msg = errormsg.format(id_or_name, str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_nas_server(self, name=None, id=None):
        """Get the instance of a NAS Server.
            :param name: The NAS Server name
            :param id: The NAS Server id
            :return: instance of the respective NAS Server if exists.
        """

        errormsg = "Failed to get the NAS Server {0} with error {1}"
        id_or_name = name if name else id

        try:
            obj_nas = self.unity_conn.get_nas_server(_id=id, name=name)
            if id and obj_nas.existed:
                LOG.info("Successfully got the nas server object %s",
                         obj_nas)
                return obj_nas
            elif name:
                LOG.info("Successfully got the nas server object %s ",
                         obj_nas)
                return obj_nas
            else:
                msg = "Failed to get the nas server with {0}".format(
                    id_or_name)
                LOG.error(msg)
                self.module.fail_json(msg=msg)

        except Exception as e:
            msg = errormsg.format(name, str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_pool(self, pool_name=None, pool_id=None):
        """Get the instance of a pool.
            :param pool_name: The name of the pool
            :param pool_id: The id of the pool
            :return: Dict containing pool details if exists
        """

        id_or_name = pool_id if pool_id else pool_name
        errormsg = "Failed to get the pool {0} with error {1}"

        try:
            obj_pool = self.unity_conn.get_pool(name=pool_name, _id=pool_id)

            if pool_id and obj_pool.existed:
                LOG.info("Successfully got the pool object %s",
                         obj_pool)
                return obj_pool
            if pool_name:
                LOG.info("Successfully got pool %s", obj_pool)
                return obj_pool
            else:
                msg = "Failed to get the pool with {0}".format(
                    id_or_name)
                LOG.error(msg)
                self.module.fail_json(msg=msg)

        except Exception as e:
            msg = errormsg.format(id_or_name, str(e))
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def get_tiering_policy_enum(self, tiering_policy):
        """Get the tiering_policy enum.
             :param tiering_policy: The tiering_policy string
             :return: tiering_policy enum
        """

        if tiering_policy in utils.TieringPolicyEnum.__members__:
            return utils.TieringPolicyEnum[tiering_policy]
        else:
            errormsg = "Invalid choice {0} for tiering policy".format(
                tiering_policy)
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_supported_protocol_enum(self, supported_protocol):
        """Get the supported_protocol enum.
             :param supported_protocol: The supported_protocol string
             :return: supported_protocol enum
        """

        supported_protocol = "MULTI_PROTOCOL" if \
            supported_protocol == "MULTIPROTOCOL" else supported_protocol
        if supported_protocol in utils.FSSupportedProtocolEnum.__members__:
            return utils.FSSupportedProtocolEnum[supported_protocol]
        else:
            errormsg = "Invalid choice {0} for supported_protocol".format(
                supported_protocol)
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_locking_policy_enum(self, locking_policy):
        """Get the locking_policy enum.
             :param locking_policy: The locking_policy string
             :return: locking_policy enum
        """
        if locking_policy in utils.FSLockingPolicyEnum.__members__:
            return utils.FSLockingPolicyEnum[locking_policy]
        else:
            errormsg = "Invalid choice {0} for locking_policy".format(
                locking_policy)
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_access_policy_enum(self, access_policy):
        """Get the access_policy enum.
             :param access_policy: The access_policy string
             :return: access_policy enum
        """
        if access_policy in utils.AccessPolicyEnum.__members__:
            return utils.AccessPolicyEnum[access_policy]
        else:
            errormsg = "Invalid choice {0} for access_policy".format(
                access_policy)
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def create_filesystem(self, name, obj_pool, obj_nas_server, size):
        """Create a FileSystem.
            :param name: Name of the FileSystem
            :param obj_pool: Storage Pool obj instance
            :param obj_nas_server: NAS Server obj instance
            :param size: Total size of a filesystem in bytes
            :return: FileSystem object on successful creation
        """
        try:

            supported_protocol = self.module.params['supported_protocols']
            supported_protocol = self.get_supported_protocol_enum(
                supported_protocol) if supported_protocol else None
            is_thin = self.module.params['is_thin']

            tiering_policy = self.module.params['tiering_policy']
            tiering_policy = self.get_tiering_policy_enum(tiering_policy) \
                if tiering_policy else None

            obj_fs = utils.UnityFileSystem.create(
                self.unity_conn._cli,
                pool=obj_pool,
                nas_server=obj_nas_server,
                name=name,
                size=size,
                proto=supported_protocol,
                is_thin=is_thin,
                tiering_policy=tiering_policy)

            LOG.info("Successfully created file system , %s", obj_fs)
            return obj_fs

        except Exception as e:
            errormsg = "Create filesystem {0} operation  failed" \
                       " with error {1}".format(name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def delete_filesystem(self, id):
        """Delete a FileSystem.
        :param id: The object instance of the filesystem to be deleted
        """

        try:
            obj_fs = self.get_filesystem(id=id)
            obj_fs_dict = obj_fs._get_properties()
            if obj_fs_dict['cifs_share'] is not None:
                errormsg = "The Filesystem has SMB Shares. Hence deleting " \
                           "this filesystem is not safe."
                LOG.error(errormsg)
                self.module.fail_json(msg=errormsg)
            if obj_fs_dict['nfs_share'] is not None:
                errormsg = "The FileSystem has NFS Exports. Hence deleting " \
                           "this filesystem is not safe."
                LOG.error(errormsg)
                self.module.fail_json(msg=errormsg)
            obj_fs.delete()
            return True

        except Exception as e:
            errormsg = "Delete operation of FileSystem id:{0} " \
                       "failed with error {1}".format(id,
                                                      str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def is_modify_required(self, obj_fs, cap_unit):
        """Checks if any modify required for filesystem attributes
        :param obj_fs: filesystem instance
        :param cap_unit: capacity unit
        :return: filesystem to update dict
        """
        try:
            to_update = {}
            obj_fs = obj_fs.update()
            description = self.module.params['description']

            if description is not None and description != obj_fs.description:
                to_update.update({'description': description})

            size = self.module.params['size']
            if size and cap_unit:
                size_byte = int(utils.get_size_bytes(size, cap_unit))
                if size_byte < obj_fs.size_total:
                    self.module.fail_json(msg="Filesystem size can be "
                                              "expanded only")
                elif size_byte > obj_fs.size_total:
                    to_update.update({'size': size_byte})

            tiering_policy = self.module.params['tiering_policy']
            if tiering_policy and self.get_tiering_policy_enum(
                    tiering_policy) != obj_fs.tiering_policy:
                to_update.update({'tiering_policy':
                                  self.get_tiering_policy_enum(
                                      tiering_policy)})

            is_thin = self.module.params['is_thin']
            if is_thin is not None and is_thin != obj_fs.is_thin_enabled:
                to_update.update({'is_thin': is_thin})

            data_reduction = self.module.params['data_reduction']
            if data_reduction is not None and \
                    data_reduction != obj_fs.is_data_reduction_enabled:
                to_update.update({'is_compression': data_reduction})

            access_policy = self.module.params['access_policy']
            if access_policy and self.get_access_policy_enum(
                    access_policy) != obj_fs.access_policy:
                to_update.update({'access_policy':
                                  self.get_access_policy_enum(access_policy)})

            locking_policy = self.module.params['locking_policy']
            if locking_policy and self.get_locking_policy_enum(
                    locking_policy) != obj_fs.locking_policy:
                to_update.update({'locking_policy':
                                  self.get_locking_policy_enum(
                                      locking_policy)})

            snap_sch = obj_fs.storage_resource.snap_schedule

            if self.snap_sch_id is not None:
                if self.snap_sch_id == "":
                    if snap_sch and snap_sch.id != self.snap_sch_id:
                        to_update.update({'is_snap_schedule_paused': False})
                elif snap_sch is None or snap_sch.id != self.snap_sch_id:
                    to_update.update({'snap_sch_id': self.snap_sch_id})

            smb_properties = self.module.params['smb_properties']
            if smb_properties:
                sync_writes_enabled = \
                    smb_properties['is_smb_sync_writes_enabled']
                oplocks_enabled = \
                    smb_properties['is_smb_op_locks_enabled']
                notify_on_write = \
                    smb_properties['is_smb_notify_on_write_enabled']
                notify_on_access = \
                    smb_properties['is_smb_notify_on_access_enabled']
                notify_on_change_dir_depth = \
                    smb_properties['smb_notify_on_change_dir_depth']

                if sync_writes_enabled is not None and \
                        sync_writes_enabled != obj_fs.is_cifs_sync_writes_enabled:
                    to_update.update(
                        {'is_cifs_sync_writes_enabled': sync_writes_enabled})

                if oplocks_enabled is not None and \
                        oplocks_enabled != obj_fs.is_cifs_op_locks_enabled:
                    to_update.update(
                        {'is_cifs_op_locks_enabled': oplocks_enabled})

                if notify_on_write is not None and \
                        notify_on_write != \
                        obj_fs.is_cifs_notify_on_write_enabled:
                    to_update.update(
                        {'is_cifs_notify_on_write_enabled': notify_on_write})

                if notify_on_access is not None and \
                        notify_on_access != \
                        obj_fs.is_cifs_notify_on_access_enabled:
                    to_update.update(
                        {'is_cifs_notify_on_access_enabled':
                         notify_on_access})

                if notify_on_change_dir_depth is not None and \
                        notify_on_change_dir_depth != \
                        obj_fs.cifs_notify_on_change_dir_depth:
                    to_update.update(
                        {'cifs_notify_on_change_dir_depth':
                         notify_on_change_dir_depth})
            if len(to_update) > 0:
                return to_update
            else:
                return None

        except Exception as e:
            errormsg = "Failed to determine if FileSystem id: {0}" \
                       " modification required with error {1}".format(obj_fs.id,
                                                                      str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_filesystem(self, update_dict, obj_fs):
        """ modifes attributes for a filesystem instance
        :param update_dict: modify dict
        :return: True on Success
        """
        try:
            adv_smb_params = [
                'is_cifs_sync_writes_enabled',
                'is_cifs_op_locks_enabled',
                'is_cifs_notify_on_write_enabled',
                'is_cifs_notify_on_access_enabled',
                'cifs_notify_on_change_dir_depth']

            cifs_fs_payload = {}
            fs_update_payload = {}

            for smb_param in adv_smb_params:
                if smb_param in update_dict.keys():
                    cifs_fs_payload.update({smb_param: update_dict[smb_param]})

            LOG.debug("CIFS Modify Payload: %s", cifs_fs_payload)

            cifs_fs_parameters = obj_fs.prepare_cifs_fs_parameters(
                **cifs_fs_payload)

            fs_update_params = [
                'size',
                'is_thin',
                'tiering_policy',
                'is_compression',
                'access_policy',
                'locking_policy',
                'description',
                'cifs_fs_parameters']

            for fs_param in fs_update_params:
                if fs_param in update_dict.keys():
                    fs_update_payload.update({fs_param: update_dict[fs_param]})

            if cifs_fs_parameters:
                fs_update_payload.update(
                    {'cifs_fs_parameters': cifs_fs_parameters})

            if "snap_sch_id" in update_dict.keys():
                fs_update_payload.update(
                    {'snap_schedule_parameters': {'snapSchedule':
                     {'id': update_dict.get('snap_sch_id')}
                    }}
                )
            elif "is_snap_schedule_paused" in update_dict.keys():
                fs_update_payload.update(
                    {'snap_schedule_parameters': {'isSnapSchedulePaused': False}
                     })

            obj_fs = obj_fs.update()
            resp = obj_fs.modify(**fs_update_payload)
            LOG.info("Successfully modified the FS with response %s", resp)

        except Exception as e:
            errormsg = "Failed to modify FileSystem instance id: {0}" \
                       " with error {1}".format(obj_fs.id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_filesystem_display_attributes(self, obj_fs):
        """get display filesystem attributes
        :param obj_fs: filesystem instance
        :return: filesystem dict to display
        """
        try:
            obj_fs = obj_fs.update()
            filesystem_details = obj_fs._get_properties()
            filesystem_details['size_total_with_unit'] = utils. \
                convert_size_with_unit(int(filesystem_details['size_total']))
            if obj_fs.pool:
                filesystem_details.update(
                    {'pool': {'name': obj_fs.pool.name,
                              'id': obj_fs.pool.id}})
            if obj_fs.nas_server:
                filesystem_details.update(
                    {'nas_server': {'name': obj_fs.nas_server.name,
                                    'id': obj_fs.nas_server.id}})
            snap_list = []
            if obj_fs.has_snap():
                for snap in obj_fs.snapshots:
                    d = {'name': snap.name, 'id': snap.id}
                    snap_list.append(d)
            filesystem_details['snapshots'] = snap_list

            if obj_fs.storage_resource.snap_schedule:
                filesystem_details['snap_schedule_id'] = obj_fs.storage_resource.snap_schedule.id
                filesystem_details['snap_schedule_name'] = obj_fs.storage_resource.snap_schedule.name

            quota_config_obj = self.get_quota_config_details(obj_fs)

            if quota_config_obj:

                hard_limit = utils.convert_size_with_unit(
                    quota_config_obj.default_hard_limit)
                soft_limit = utils.convert_size_with_unit(
                    quota_config_obj.default_soft_limit)
                grace_period = get_time_with_unit(
                    quota_config_obj.grace_period)

                filesystem_details.update({'quota_config':
                                          {'id': quota_config_obj.id,
                                           'default_hard_limit': hard_limit,
                                           'default_soft_limit': soft_limit,
                                           'is_user_quota_enabled':
                                               quota_config_obj.is_user_quota_enabled,
                                           'quota_policy': quota_config_obj._get_properties()[
                                               'quota_policy'],
                                           'grace_period': grace_period}
                                           })
            filesystem_details['replication_sessions'] = []
            fs_repl_sessions = self.get_replication_session(obj_fs)
            if fs_repl_sessions:
                filesystem_details['replication_sessions'] = \
                    fs_repl_sessions._get_properties()
            return filesystem_details

        except Exception as e:
            errormsg = "Failed to display the filesystem {0} with " \
                       "error {1}".format(obj_fs.name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def validate_input_string(self):
        """ validates the input string checks if it is empty string """
        invalid_string = ""
        try:
            for key in self.module.params:
                val = self.module.params[key]
                if key == "description" or key == "snap_schedule_name" \
                          or key == "snap_schedule_id":
                    continue
                if isinstance(val, str) \
                        and val == invalid_string:
                    errmsg = 'Invalid input parameter "" for {0}'.format(
                        key)
                    self.module.fail_json(msg=errmsg)
            if self.module.params['replication_params'] and self.module.params['replication_state'] is None:
                self.module.fail_json(msg="Please specify replication_state along with replication_params")
        except Exception as e:
            errormsg = "Failed to validate the module param with " \
                       "error {0}".format(str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def resolve_to_snapschedule_id(self, params):
        """ Get snapshot id for a give snap schedule name
        :param params: snap schedule name or id
        :return: snap schedule id after validation
        """

        try:
            snap_sch_id = None
            snapshot_schedule = {}
            if params["name"]:
                snapshot_schedule = utils.UnitySnapScheduleList.get(self.unity_conn._cli, name=params["name"])
            elif params["id"]:
                snapshot_schedule = utils.UnitySnapScheduleList.get(self.unity_conn._cli, id=params["id"])

            if snapshot_schedule:
                snap_sch_id = snapshot_schedule.id[0]

            if not snap_sch_id:
                errormsg = "Failed to find the snapshot schedule id against given name " \
                           "or id: {0}".format(params["name"]), (params["id"])
                LOG.error(errormsg)
                self.module.fail_json(msg=errormsg)

            return snap_sch_id

        except Exception as e:
            errormsg = "Failed to find the snapshot schedules with " \
                       "error {0}".format(str(e))

    def get_quota_config_details(self, obj_fs):
        """
        Get the quota config ID mapped to the filesystem
        :param obj_fs: Filesystem instance
        :return: Quota config object if exists else None
        """
        try:
            all_quota_config = self.unity_conn.get_quota_config(filesystem=obj_fs)
            fs_id = obj_fs.id

            if len(all_quota_config) == 0:
                LOG.error("The quota_config object for new filesystem "
                          "is not updated yet.")
                return None

            for quota_config in range(len(all_quota_config)):
                if fs_id and all_quota_config[quota_config].filesystem.id == fs_id and \
                        not all_quota_config[quota_config].tree_quota:
                    msg = "Quota config id for filesystem %s is %s" \
                          % (fs_id, all_quota_config[quota_config].id)
                    LOG.info(msg)
                    return all_quota_config[quota_config]

        except Exception as e:
            errormsg = "Failed to fetch quota config for filesystem {0} " \
                       " with error {1}".format(fs_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_quota_config(self, quota_config_obj, quota_config_params):
        """
        Modify default quota config settings of newly created filesystem.
        The default setting of quota config after filesystem creation is:
        default_soft_limit and default_hard_limit are 0,
        is_user_quota_enabled is false,
        grace_period is 7 days and,
        quota_policy is FILE_SIZE.
        :param quota_config_obj: Quota config instance
        :param quota_config_params: Quota config parameters to be modified
        :return: Boolean whether quota config is modified
        """

        if quota_config_params:
            soft_limit = quota_config_params['default_soft_limit']
            hard_limit = quota_config_params['default_hard_limit']
            is_user_quota_enabled = quota_config_params['is_user_quota_enabled']
            quota_policy = quota_config_params['quota_policy']
            grace_period = quota_config_params['grace_period']
            cap_unit = quota_config_params['cap_unit']
            gp_unit = quota_config_params['grace_period_unit']

        if soft_limit:
            soft_limit_in_bytes = utils.get_size_bytes(soft_limit, cap_unit)
        else:
            soft_limit_in_bytes = quota_config_obj.default_soft_limit

        if hard_limit:
            hard_limit_in_bytes = utils.get_size_bytes(hard_limit, cap_unit)
        else:
            hard_limit_in_bytes = quota_config_obj.default_hard_limit

        if grace_period:
            grace_period_in_sec = get_time_in_seconds(grace_period, gp_unit)
        else:
            grace_period_in_sec = quota_config_obj.grace_period

        policy_enum = None
        policy_enum_val = None
        if quota_policy:
            if utils.QuotaPolicyEnum[quota_policy]:
                policy_enum = utils.QuotaPolicyEnum[quota_policy]
                policy_enum_val = \
                    utils.QuotaPolicyEnum[quota_policy]._get_properties()['value']
            else:
                errormsg = "Invalid choice {0} for quota policy".format(
                    quota_policy)
                LOG.error(errormsg)
                self.module.fail_json(msg=errormsg)

        # Verify if modify is required. If not required, return False
        if quota_config_obj.default_hard_limit == hard_limit_in_bytes and \
                quota_config_obj.default_soft_limit == soft_limit_in_bytes and \
                quota_config_obj.grace_period == grace_period_in_sec and \
                ((quota_policy is not None and
                  quota_config_obj.quota_policy == policy_enum) or
                 quota_policy is None) and \
                (is_user_quota_enabled is None or
                 (is_user_quota_enabled is not None and
                  is_user_quota_enabled == quota_config_obj.is_user_quota_enabled)):
            return False

        try:
            resp = self.unity_conn.modify_quota_config(
                quota_config_id=quota_config_obj.id,
                grace_period=grace_period_in_sec,
                default_hard_limit=hard_limit_in_bytes,
                default_soft_limit=soft_limit_in_bytes,
                is_user_quota_enabled=is_user_quota_enabled,
                quota_policy=policy_enum_val)
            LOG.info("Successfully modified the quota config with response %s", resp)
            return True

        except Exception as e:
            errormsg = "Failed to modify quota config for filesystem {0} " \
                       " with error {1}".format(quota_config_obj.filesystem.id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def update_replication_params(self, replication_params):
        ''' Update replication params '''
        try:
            if replication_params['replication_type'] == 'remote' or \
                    (replication_params['replication_type'] is None and
                     replication_params['remote_system']):
                connection_params = {
                    'unispherehost': replication_params['remote_system']['remote_system_host'],
                    'username': replication_params['remote_system']['remote_system_username'],
                    'password': replication_params['remote_system']['remote_system_password'],
                    'validate_certs': replication_params['remote_system']['remote_system_verifycert'],
                    'port': replication_params['remote_system']['remote_system_port']
                }
                remote_system_conn = utils.get_unity_unisphere_connection(
                    connection_params, application_type)
                replication_params['remote_system_name'] = remote_system_conn.name
                if replication_params['destination_pool_name'] is not None:
                    pool_object = \
                        remote_system_conn.get_pool(name=replication_params['destination_pool_name'])
                    replication_params['destination_pool_id'] = pool_object.id
            else:
                if replication_params['destination_pool_name'] is not None:
                    pool_object = \
                        self.unity_conn.get_pool(name=replication_params['destination_pool_name'])
                    replication_params['destination_pool_id'] = pool_object.id
        except Exception as e:
            errormsg = "Updating replication params failed" \
                       " with error %s" % str(e)
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def validate_rpo(self, replication_params):
        ''' Validates rpo based on replication mode '''
        if replication_params['replication_mode'] == 'asynchronous' and \
                replication_params['rpo'] is None:
            errormsg = "rpo is required together with 'asynchronous' replication_mode."
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

        rpo, replication_mode = replication_params['rpo'], replication_params[
            'replication_mode']

        if rpo and replication_mode:

            rpo_criteria = {
                "asynchronous": lambda n: 5 <= n <= 1440,
                "synchronous": lambda n: n == 0,
                "manual": lambda n: n == -1
            }

            if rpo and not rpo_criteria[replication_mode](rpo):
                errormsg = f"Invalid rpo value - {rpo} for " \
                           f"{replication_mode} replication mode."
                LOG.error(errormsg)
                self.module.fail_json(msg=errormsg)

    def validate_replication_params(self, replication_params):
        ''' Validate replication params '''
        if not replication_params:
            errormsg = "Please specify replication_params to enable replication."
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

        if replication_params['destination_pool_id'] is not None and \
                replication_params['destination_pool_name'] is not None:
            errormsg = "'destination_pool_id' and 'destination_pool_name' is mutually exclusive."
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

        self.validate_rpo(replication_params)
        # Validate replication type
        if replication_params['replication_type'] == 'remote' and replication_params['remote_system'] is None:
            errormsg = "Remote_system is required together with 'remote' replication_type"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def validate_create_replication_params(self, replication_params):
        ''' Validate replication params '''

        if replication_params['destination_pool_id'] is None and \
                replication_params['destination_pool_name'] is None:
            errormsg = "Either 'destination_pool_id' or 'destination_pool_name' is required to enable replication."
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

        keys = ['replication_mode', 'replication_type']
        for key in keys:
            if replication_params[key] is None:
                errormsg = "Please specify %s to enable replication." % key
                LOG.error(errormsg)
                self.module.fail_json(msg=errormsg)

    def modify_replication_session(self, obj_fs, repl_session, replication_params):
        """ Modify the replication session
            :param: obj_fs: Filesystem object
            :param: repl_session: Replication session to be modified
            :param: replication_params: Module input params
            :return: True if modification is successful
        """
        try:
            LOG.info("Modifying replication session of filesystem %s", obj_fs.name)
            modify_payload = {}
            rpo = 0
            if replication_params['replication_mode']:
                if replication_params['replication_mode'] == 'manual':
                    rpo = -1
                elif replication_params['replication_mode'] == 'synchronous':
                    rpo = 0
                elif replication_params['replication_mode'] == 'asynchronous':
                    rpo = replication_params.get('rpo', 0)
            elif replication_params['rpo']:
                rpo = replication_params['rpo']
            name = repl_session.name
            if replication_params['new_replication_name'] and \
                    name != replication_params['new_replication_name']:
                name = replication_params['new_replication_name']

            if repl_session.name != name:
                modify_payload['name'] = name
            if ((replication_params['replication_mode'] or replication_params['rpo']) and
                    repl_session.max_time_out_of_sync != rpo):
                modify_payload['max_time_out_of_sync'] = rpo

            if modify_payload:
                repl_session.modify(**modify_payload)
                return True

            return False
        except Exception as e:
            errormsg = "Modifying replication session failed with error %s" % e
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def enable_replication(self, obj_fs, replication_params):
        """ Enable the replication session
            :param: obj_fs: Filesystem object
            :param: replication_params: Module input params
            :return: True if enabling replication is successful
        """
        try:
            self.validate_replication_params(replication_params)
            self.update_replication_params(replication_params)

            repl_session = \
                self.get_replication_session_on_filter(obj_fs, replication_params, "modify")
            if repl_session:
                return self.modify_replication_session(obj_fs, repl_session, replication_params)

            self.validate_create_replication_params(replication_params)
            replication_args_list = get_replication_args_list(replication_params)
            if 'remote_system_name' in replication_params:
                remote_system_name = replication_params['remote_system_name']
                remote_system_list = self.unity_conn.get_remote_system()
                for remote_system in remote_system_list:
                    if remote_system.name == remote_system_name:
                        replication_args_list['remote_system'] = remote_system
                        break
                if 'remote_system' not in replication_args_list.keys():
                    errormsg = "Remote system %s is not found" % (remote_system_name)
                    LOG.error(errormsg)
                    self.module.fail_json(msg=errormsg)

            LOG.info("Enabling replication to the filesystem %s", obj_fs.name)
            obj_fs.replicate_with_dst_resource_provisioning(**replication_args_list)
            return True
        except Exception as e:
            errormsg = "Enabling replication to the filesystem %s failed " \
                       "with error %s" % (obj_fs.name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def disable_replication(self, obj_fs, replication_params):
        """ Remove replication from the filesystem
            :param: replication_params: Module input params
            :return: True if disabling replication is successful
        """
        try:
            LOG.info(("Disabling replication on the filesystem %s", obj_fs.name))
            if replication_params:
                self.update_replication_params(replication_params)
            repl_session = \
                self.get_replication_session_on_filter(obj_fs, replication_params, "delete")
            if repl_session:
                repl_session.delete()
                return True
            return False
        except Exception as e:
            errormsg = "Disabling replication on the filesystem %s failed " \
                       "with error %s" % (obj_fs.name, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_replication_session_on_filter(self, obj_fs, replication_params, action):
        if replication_params and replication_params['remote_system']:
            repl_session = \
                self.get_replication_session(obj_fs, filter_key="remote_system_name",
                                             replication_params=replication_params)
        elif replication_params and replication_params['replication_name']:
            repl_session = \
                self.get_replication_session(obj_fs, filter_key="name",
                                             name=replication_params['replication_name'])
        else:
            repl_session = self.get_replication_session(obj_fs, action=action)
            if repl_session and action and replication_params and \
                    replication_params['replication_type'] == 'local' and \
                    repl_session.remote_system.name != self.unity_conn.name:
                return None

        return repl_session

    def get_replication_session(self, obj_fs, filter_key=None, replication_params=None, name=None, action=None):
        """ Retrieves the replication sessions configured for the filesystem
            :param: obj_fs: Filesystem object
            :param: filter_key: Key to filter replication sessions
            :param: replication_params: Module input params
            :param: name: Replication session name
            :param: action: Specifies modify or delete action on replication session
            :return: Replication session details
        """
        try:
            repl_session = self.unity_conn.get_replication_session(src_resource_id=obj_fs.storage_resource.id)
            if not filter_key and repl_session:
                if len(repl_session) > 1:
                    if action:
                        error_msg = 'There are multiple replication sessions for the filesystem.'\
                                    ' Please specify replication_name in replication_params to %s.' % action
                        self.module.fail_json(msg=error_msg)
                    return repl_session
                return repl_session[0]
            for session in repl_session:
                if filter_key == 'remote_system_name' and \
                        session.remote_system.name == replication_params['remote_system_name']:
                    return session
                if filter_key == 'name' and session.name == name:
                    return session
            return None
        except Exception as e:
            errormsg = "Retrieving replication session on the filesystem failed " \
                       "with error %s", str(e)
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def perform_module_operation(self):
        """
        Perform different actions on filesystem module based on parameters
        passed in the playbook
        """
        filesystem_name = self.module.params['filesystem_name']
        filesystem_id = self.module.params['filesystem_id']
        nas_server_name = self.module.params['nas_server_name']
        nas_server_id = self.module.params['nas_server_id']
        pool_name = self.module.params['pool_name']
        pool_id = self.module.params['pool_id']
        size = self.module.params['size']
        cap_unit = self.module.params['cap_unit']
        quota_config = self.module.params['quota_config']
        replication_params = self.module.params['replication_params']
        replication_state = self.module.params['replication_state']
        state = self.module.params['state']
        snap_schedule_name = self.module.params['snap_schedule_name']
        snap_schedule_id = self.module.params['snap_schedule_id']

        # result is a dictionary to contain end state and FileSystem details
        changed = False
        result = dict(
            changed=False,
            filesystem_details={}
        )

        to_modify_dict = None
        filesystem_details = None
        quota_config_obj = None

        self.validate_input_string()

        if size is not None and size == 0:
            self.module.fail_json(msg="Size can not be 0 (Zero)")

        if size and not cap_unit:
            cap_unit = 'GB'

        if quota_config:
            if (quota_config['default_hard_limit'] is not None
                or quota_config['default_soft_limit'] is not None) and \
                    not quota_config['cap_unit']:
                quota_config['cap_unit'] = 'GB'

            if quota_config['grace_period'] is not None \
                    and quota_config['grace_period_unit'] is None:
                quota_config['grace_period_unit'] = 'days'

            if quota_config['grace_period'] is not None \
                    and quota_config['grace_period'] <= 0:
                self.module.fail_json(msg="Invalid grace_period provided. "
                                          "Must be greater than 0.")

            if quota_config['default_soft_limit'] is not None \
                    and utils.is_size_negative(quota_config['default_soft_limit']):
                self.module.fail_json(msg="Invalid default_soft_limit provided. "
                                          "Must be greater than or equal to 0.")

            if quota_config['default_hard_limit'] is not None \
                    and utils.is_size_negative(quota_config['default_hard_limit']):
                self.module.fail_json(msg="Invalid default_hard_limit provided. "
                                          "Must be greater than or equal to 0.")

        if (cap_unit is not None) and not size:
            self.module.fail_json(msg="cap_unit can be specified along "
                                      "with size")

        nas_server = None
        if nas_server_name or nas_server_id:
            nas_server = self.get_nas_server(
                name=nas_server_name, id=nas_server_id)

        obj_pool = None
        if pool_name or pool_id:
            obj_pool = self.get_pool(pool_name=pool_name, pool_id=pool_id)

        obj_fs = None
        obj_fs = self.get_filesystem(name=filesystem_name,
                                     id=filesystem_id,
                                     obj_nas_server=nas_server)

        self.snap_sch_id = None
        if snap_schedule_name or snap_schedule_id:
            snap_schedule_params = {
                "name": snap_schedule_name,
                "id": snap_schedule_id
            }
            self.snap_sch_id = self.resolve_to_snapschedule_id(snap_schedule_params)
        elif snap_schedule_name == "" or snap_schedule_id == "":
            self.snap_sch_id = ""

        if obj_fs:
            filesystem_details = obj_fs._get_properties()
            filesystem_id = obj_fs.get_id()
            to_modify_dict = self.is_modify_required(obj_fs, cap_unit)
            LOG.info("From Mod Op, to_modify_dict: %s", to_modify_dict)

        if state == 'present' and not filesystem_details:
            if not filesystem_name:
                msg_noname = "FileSystem with id {0} is not found, unable to " \
                             "create a FileSystem without a valid " \
                             "filesystem_name".format(filesystem_id)
                self.module.fail_json(msg=msg_noname)

            if not pool_name and not pool_id:
                self.module.fail_json(msg="pool_id or pool_name is required "
                                          "to create new filesystem")
            if not size:
                self.module.fail_json(msg="Size is required to create"
                                          " a filesystem")
            size = utils.get_size_bytes(size, cap_unit)

            obj_fs = self.create_filesystem(name=filesystem_name,
                                            obj_pool=obj_pool,
                                            obj_nas_server=nas_server,
                                            size=size)

            LOG.debug("Successfully created filesystem , %s", obj_fs)
            filesystem_id = obj_fs.id
            filesystem_details = obj_fs._get_properties()
            to_modify_dict = self.is_modify_required(obj_fs, cap_unit)
            LOG.debug("Got filesystem id , %s", filesystem_id)
            changed = True

        if state == 'present' and filesystem_details and to_modify_dict:
            self.modify_filesystem(update_dict=to_modify_dict, obj_fs=obj_fs)
            changed = True

        """
        Set quota configuration
        """
        if state == "present" and filesystem_details and quota_config:
            quota_config_obj = self.get_quota_config_details(obj_fs)

            if quota_config_obj is not None:
                is_quota_config_modified = self.modify_quota_config(
                    quota_config_obj=quota_config_obj,
                    quota_config_params=quota_config)

                if is_quota_config_modified:
                    changed = True
            else:
                self.module.fail_json(msg="One or more operations related"
                                          " to this task failed because the"
                                          " new object created could not be fetched."
                                          " Please rerun the task for expected result.")

        if state == 'present' and filesystem_details and replication_state is not None:
            if replication_state == 'enable':
                changed = self.enable_replication(obj_fs, replication_params)
            else:
                changed = self.disable_replication(obj_fs, replication_params)

        if state == 'absent' and filesystem_details:
            changed = self.delete_filesystem(filesystem_id)
            filesystem_details = None

        if state == 'present' and filesystem_details:
            filesystem_details = self.get_filesystem_display_attributes(
                obj_fs=obj_fs)

        result['changed'] = changed
        result['filesystem_details'] = filesystem_details
        self.module.exit_json(**result)


def get_time_in_seconds(time, time_units):
    """This method get time is seconds"""
    min_in_sec = 60
    hour_in_sec = 60 * 60
    day_in_sec = 24 * 60 * 60
    if time is not None and time > 0:
        if time_units in 'minutes':
            return time * min_in_sec
        elif time_units in 'hours':
            return time * hour_in_sec
        elif time_units in 'days':
            return time * day_in_sec
        else:
            return time
    else:
        return 0


def get_time_with_unit(time):
    """This method sets seconds in minutes, hours or days."""
    sec_in_min = 60
    sec_in_hour = 60 * 60
    sec_in_day = 24 * 60 * 60

    if time % sec_in_day == 0:
        time = time / sec_in_day
        unit = 'days'

    elif time % sec_in_hour == 0:
        time = time / sec_in_hour
        unit = 'hours'

    else:
        time = time / sec_in_min
        unit = 'minutes'
    return "%s %s" % (time, unit)


def get_replication_args_list(replication_params):
    """Returns the replication args for payload"""
    replication_args_list = {
        'dst_pool_id': replication_params['destination_pool_id']
    }

    if replication_params['replication_name']:
        replication_args_list['replication_name'] = replication_params['replication_name']

    if 'replication_mode' in replication_params:
        if replication_params['replication_mode'] == 'asynchronous':
            replication_args_list['max_time_out_of_sync'] = replication_params['rpo']
        elif replication_params['replication_mode'] == 'synchronous':
            replication_args_list['max_time_out_of_sync'] = 0
        else:
            replication_args_list['max_time_out_of_sync'] = -1

    return replication_args_list


def get_filesystem_parameters():
    """This method provide parameters required for the ansible filesystem
       module on Unity"""
    return dict(
        filesystem_name=dict(required=False, type='str'),
        filesystem_id=dict(required=False, type='str'),
        nas_server_name=dict(required=False, type='str'),
        nas_server_id=dict(required=False, type='str'),
        description=dict(required=False, type='str'),
        pool_name=dict(required=False, type='str'),
        pool_id=dict(required=False, type='str'),
        size=dict(required=False, type='int'),
        cap_unit=dict(required=False, type='str', choices=['GB', 'TB']),
        is_thin=dict(required=False, type='bool'),
        data_reduction=dict(required=False, type='bool'),
        supported_protocols=dict(required=False, type='str',
                                 choices=['NFS', 'CIFS', 'MULTIPROTOCOL']),
        smb_properties=dict(type='dict', options=dict(
            is_smb_sync_writes_enabled=dict(type='bool'),
            is_smb_notify_on_access_enabled=dict(type='bool'),
            is_smb_op_locks_enabled=dict(type='bool'),
            is_smb_notify_on_write_enabled=dict(type='bool'),
            smb_notify_on_change_dir_depth=dict(type='int')
        )),
        access_policy=dict(required=False, type='str',
                           choices=['NATIVE', 'UNIX', 'WINDOWS']),
        locking_policy=dict(required=False, type='str',
                            choices=['ADVISORY', 'MANDATORY']),
        tiering_policy=dict(required=False, type='str', choices=[
            'AUTOTIER_HIGH', 'AUTOTIER', 'HIGHEST', 'LOWEST']),
        snap_schedule_name=dict(required=False, type='str'),
        snap_schedule_id=dict(required=False, type='str'),
        quota_config=dict(required=False, type='dict', options=dict(
            grace_period=dict(required=False, type='int'),
            grace_period_unit=dict(required=False, type='str', choices=['minutes', 'hours', 'days']),
            default_hard_limit=dict(required=False, type='int'),
            default_soft_limit=dict(required=False, type='int'),
            is_user_quota_enabled=dict(required=False, type='bool'),
            quota_policy=dict(required=False, type='str', choices=['FILE_SIZE', 'BLOCKS']),
            cap_unit=dict(required=False, type='str', choices=['MB', 'GB', 'TB']),
        ), mutually_exclusive=[['is_user_quota_enabled', 'quota_policy']]),
        replication_params=dict(type='dict', options=dict(
            replication_name=dict(type='str'),
            new_replication_name=dict(type='str'),
            replication_type=dict(type='str', choices=['local', 'remote']),
            replication_mode=dict(type='str',
                                  choices=['synchronous', 'asynchronous',
                                           'manual']),
            rpo=dict(type='int'),
            remote_system=dict(type='dict',
                               options=dict(
                                    remote_system_host=dict(type='str', required=True),
                                    remote_system_verifycert=dict(type='bool', required=False,
                                                                  default=True),
                                    remote_system_username=dict(type='str', required=True),
                                    remote_system_password=dict(type='str', required=True, no_log=True),
                                    remote_system_port=dict(type='int', required=False, default=443)
                               )),
            destination_pool_name=dict(type='str'),
            destination_pool_id=dict(type='str')
        )),
        replication_state=dict(type='str', choices=['enable', 'disable']),
        state=dict(required=True, type='str', choices=['present', 'absent'])
    )


def main():
    """ Create Unity FileSystem object and perform action on it
        based on user input from playbook"""
    obj = Filesystem()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
