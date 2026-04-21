#!/usr/bin/python
# Copyright: (c) 2020-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing Filesystem Snapshots on Unity"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: filesystem_snapshot
short_description: Manage filesystem snapshot on the Unity storage system
description:
- Managing Filesystem Snapshot on the Unity storage system includes
  create filesystem snapshot, get filesystem snapshot, modify filesystem
  snapshot and delete filesystem snapshot.
version_added: '1.1.0'
extends_documentation_fragment:
  - dellemc.unity.unity
author:
- Rajshree Khare (@kharer5) <ansible.team@dell.com>
options:
  snapshot_name:
    description:
    - The name of the filesystem snapshot.
    - Mandatory parameter for creating a filesystem snapshot.
    - For all other operations either I(snapshot_name) or I(snapshot_id)
      is required.
    type: str
  snapshot_id:
    description:
    - During creation snapshot_id is auto generated.
    - For all other operations either I(snapshot_id) or I(snapshot_name)
      is required.
    type: str
  filesystem_name:
    description:
    - The name of the Filesystem for which snapshot is created.
    - For creation of filesystem snapshot either I(filesystem_name) or
      I(filesystem_id) is required.
    - Not required for other operations.
    type: str
  filesystem_id:
    description:
    - The ID of the Filesystem for which snapshot is created.
    - For creation of filesystem snapshot either I(filesystem_id) or
      I(filesystem_name) is required.
    - Not required for other operations.
    type: str
  nas_server_name:
    description:
    - The name of the NAS server in which the Filesystem is created.
    - For creation of filesystem snapshot either I(nas_server_name) or
      I(nas_server_id) is required.
    - Not required for other operations.
    type: str
  nas_server_id:
    description:
    - The ID of the NAS server in which the Filesystem is created.
    - For creation of filesystem snapshot either I(filesystem_id) or
      I(filesystem_name) is required.
    - Not required for other operations.
    type: str
  auto_delete:
    description:
    - This option specifies whether or not the filesystem snapshot will be
      automatically deleted.
    - If set to C(true), the filesystem snapshot will expire based on the pool
      auto deletion policy.
    - If set to C(false), the filesystem snapshot will not be auto deleted
      based on the pool auto deletion policy.
    - Option I(auto_delete) can not be set to C(true), if I(expiry_time) is specified.
    - If during creation neither I(auto_delete) nor I(expiry_time) is mentioned
      then the filesystem snapshot will be created keeping I(auto_delete) as
      C(true).
    - Once the I(expiry_time) is set, then the filesystem snapshot cannot be
      assigned to the auto delete policy.
    type: bool
  expiry_time:
    description:
    - This option is for specifying the date and time after which the
      filesystem snapshot will expire.
    - The time is to be mentioned in UTC timezone.
    - The format is "MM/DD/YYYY HH:MM". Year must be in 4 digits.
    type: str
  description:
    description:
    - The additional information about the filesystem snapshot can be
      provided using this option.
    - The description can be removed by passing an empty string.
    type: str
  fs_access_type:
    description:
    - Access type of the filesystem snapshot.
    - Required only during creation of filesystem snapshot.
    - If not given, snapshot's access type will be C(Checkpoint).
    type: str
    choices: ['Checkpoint' , 'Protocol']
  state:
    description:
    - The state option is used to mention the existence of the filesystem
      snapshot.
    type: str
    required: true
    choices: ['absent', 'present']
notes:
  - Filesystem snapshot cannot be deleted, if it has nfs or smb share.
  - The I(check_mode) is not supported.
'''

EXAMPLES = r'''
- name: Create Filesystem Snapshot
  filesystem_snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_name: "ansible_test_FS_snap"
    filesystem_name: "ansible_test_FS"
    nas_server_name: "lglad069"
    description: "Created using playbook"
    auto_delete: true
    fs_access_type: "Protocol"
    state: "present"

- name: Create Filesystem Snapshot with expiry time
  filesystem_snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_name: "ansible_test_FS_snap_1"
    filesystem_name: "ansible_test_FS_1"
    nas_server_name: "lglad069"
    description: "Created using playbook"
    expiry_time: "04/15/2021 2:30"
    fs_access_type: "Protocol"
    state: "present"

- name: Get Filesystem Snapshot Details using Name
  filesystem_snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_name: "ansible_test_FS_snap"
    state: "present"

- name: Get Filesystem Snapshot Details using ID
  filesystem_snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_id: "10008000403"
    state: "present"

- name: Update Filesystem Snapshot attributes
  filesystem_snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_name: "ansible_test_FS_snap"
    description: "Description updated"
    auto_delete: false
    expiry_time: "04/15/2021 5:30"
    state: "present"

- name: Update Filesystem Snapshot attributes using ID
  filesystem_snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_id: "10008000403"
    expiry_time: "04/18/2021 8:30"
    state: "present"

- name: Delete Filesystem Snapshot using Name
  filesystem_snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_name: "ansible_test_FS_snap"
    state: "absent"

- name: Delete Filesystem Snapshot using ID
  filesystem_snapshot:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    snapshot_id: "10008000403"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true

filesystem_snapshot_details:
    description: Details of the filesystem snapshot.
    returned: When filesystem snapshot exists
    type: dict
    contains:
        access_type:
            description: Access type of filesystem snapshot.
            type: str
        attached_wwn:
            description: Attached WWN details.
            type: str
        creation_time:
            description: Creation time of filesystem snapshot.
            type: str
        creator_schedule:
            description: Creator schedule of filesystem snapshot.
            type: str
        creator_type:
            description: Creator type for filesystem snapshot.
            type: str
        creator_user:
            description: Creator user for filesystem snapshot.
            type: str
        description:
            description: Description of the filesystem snapshot.
            type: str
        expiration_time:
            description: Date and time after which the filesystem snapshot
                         will expire.
            type: str
        is_auto_delete:
            description: Is the filesystem snapshot is auto deleted or not.
            type: bool
        id:
            description: Unique identifier of the filesystem snapshot
                         instance.
            type: str
        name:
            description: The name of the filesystem snapshot.
            type: str
        size:
            description: Size of the filesystem snapshot.
            type: int
        filesystem_name:
            description: Name of the filesystem for which the snapshot exists.
            type: str
        filesystem_id:
            description: Id of the filesystem for which the snapshot exists.
            type: str
        nas_server_name:
            description: Name of the NAS server on which filesystem exists.
            type: str
        nas_server_id:
            description: Id of the NAS server on which filesystem exists.
            type: str
    sample: {
        "access_type": "FilesystemSnapAccessTypeEnum.CHECKPOINT",
        "attached_wwn": null,
        "creation_time": "2022-10-21 04:42:53.951000+00:00",
        "creator_schedule": null,
        "creator_type": "SnapCreatorTypeEnum.USER_CUSTOM",
        "creator_user": {
            "id": "user_admin"
        },
        "description": "Created using playbook",
        "existed": true,
        "expiration_time": null,
        "filesystem_id": "fs_137",
        "filesystem_name": "test",
        "hash": 8739894572587,
        "host_access": null,
        "id": "171798721695",
        "io_limit_policy": null,
        "is_auto_delete": true,
        "is_modifiable": false,
        "is_modified": false,
        "is_read_only": true,
        "is_system_snap": false,
        "last_writable_time": null,
        "lun": null,
        "name": "test_FS_snap_1",
        "nas_server_id": "nas_1",
        "nas_server_name": "lglad072",
        "parent_snap": null,
        "size": 107374182400,
        "snap_group": null,
        "state": "SnapStateEnum.READY"
    }

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils
from datetime import datetime

LOG = utils.get_logger('filesystem_snapshot')

application_type = "Ansible/1.7.1"


class FilesystemSnapshot(object):
    """Class with Filesystem Snapshot operations"""

    def __init__(self):
        """ Define all parameters required by this module"""

        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_snapshot_parameters())

        mutually_exclusive = [['snapshot_name', 'snapshot_id'],
                              ['filesystem_name', 'filesystem_id'],
                              ['nas_server_name', 'nas_server_id']]

        required_one_of = [['snapshot_name', 'snapshot_id']]
        # initialize the ansible module
        self.module = AnsibleModule(argument_spec=self.module_params,
                                    supports_check_mode=False,
                                    mutually_exclusive=mutually_exclusive,
                                    required_one_of=required_one_of)
        utils.ensure_required_libs(self.module)

        # result is a dictionary that contains changed status and
        # filesystem snapshot details
        self.result = {"changed": False,
                       'filesystem_snapshot_details': {}}

        self.unity_conn = utils.get_unity_unisphere_connection(
            self.module.params, application_type)
        self.snap_obj = utils.snap.UnitySnap(self.unity_conn)
        LOG.info('Connection established with the Unity Array')

    def validate_expiry_time(self, expiry_time):
        """Validates the specified expiry_time"""
        try:
            datetime.strptime(expiry_time, '%m/%d/%Y %H:%M')
        except ValueError:
            error_msg = ("expiry_time: %s, not in MM/DD/YYYY HH:MM format." %
                         expiry_time)
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def to_update(self, fs_snapshot, description=None, auto_del=None,
                  expiry_time=None, fs_access_type=None):
        """Determines whether to update the snapshot or not"""
        snap_modify_dict = dict()

        if fs_access_type and fs_access_type != fs_snapshot.access_type:
            error_message = "Modification of access type is not allowed."
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

        # If the snapshot has is_auto_delete True,
        # Check if auto_delete in the input is either None or True
        if expiry_time and fs_snapshot.is_auto_delete \
                and (auto_del is None or auto_del):
            self.module.fail_json(msg="expiry_time can be assigned when"
                                      " auto delete is False.")
        if auto_del is not None:
            if fs_snapshot.expiration_time:
                error_msg = "expiry_time for filesystem snapshot is set." \
                            " Once it is set then snapshot cannot" \
                            " be assigned to auto_delete policy."
                self.module.fail_json(msg=error_msg)
            if auto_del != fs_snapshot.is_auto_delete:
                snap_modify_dict['is_auto_delete'] = auto_del

        if description is not None and description != fs_snapshot.description:
            snap_modify_dict['description'] = description

        if to_update_expiry_time(fs_snapshot, expiry_time):
            snap_modify_dict['expiry_time'] = expiry_time
        LOG.info("Snapshot modification details: %s", snap_modify_dict)
        return snap_modify_dict

    def update_filesystem_snapshot(self, fs_snapshot, snap_modify_dict):
        try:
            duration = None
            if 'expiry_time' in snap_modify_dict \
                    and snap_modify_dict['expiry_time']:
                duration = convert_timestamp_to_sec(
                    snap_modify_dict['expiry_time'],
                    self.unity_conn.system_time)
            if duration and duration <= 0:
                self.module.fail_json(msg="expiry_time should be after"
                                          " the current system time.")
            if 'is_auto_delete' in snap_modify_dict \
                    and snap_modify_dict['is_auto_delete'] is not None:
                auto_delete = snap_modify_dict['is_auto_delete']
            else:
                auto_delete = None
            if 'description' in snap_modify_dict \
                    and (snap_modify_dict['description']
                         or len(snap_modify_dict['description']) == 0):
                description = snap_modify_dict['description']
            else:
                description = None

            fs_snapshot.modify(retentionDuration=duration,
                               isAutoDelete=auto_delete,
                               description=description)
            fs_snapshot.update()
        except Exception as e:
            error_msg = "Failed to modify filesystem snapshot" \
                        " [name: %s , id: %s] with error %s."\
                        % (fs_snapshot.name, fs_snapshot.id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def create_filesystem_snapshot(self, snap_name, storage_id,
                                   description=None, auto_del=None,
                                   expiry_time=None, fs_access_type=None):
        try:
            duration = None
            if expiry_time:
                duration = convert_timestamp_to_sec(
                    expiry_time, self.unity_conn.system_time)
                if duration <= 0:
                    self.module.fail_json(msg="expiry_time should be after"
                                              " the current system time.")

            fs_snapshot = self.snap_obj.create(
                cli=self.unity_conn._cli, storage_resource=storage_id,
                name=snap_name, description=description,
                is_auto_delete=auto_del, retention_duration=duration,
                fs_access_type=fs_access_type)
            return fs_snapshot
        except Exception as e:
            error_msg = "Failed to create filesystem snapshot" \
                        " %s with error %s" % (snap_name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def is_snap_has_share(self, fs_snap):
        try:
            obj = self.unity_conn.get_nfs_share(snap=fs_snap) or \
                self.unity_conn.get_cifs_share(snap=fs_snap)
            if len(obj) > 0:
                LOG.info("Snapshot has %s nfs/smb share/s", len(obj))
                return True
        except Exception as e:
            msg = "Failed to get nfs/smb share from filesystem snapshot. " \
                  "error: %s" % str(e)
            LOG.error(msg)
            self.module.fail_json(msg=msg)
        return False

    def delete_fs_snapshot(self, fs_snapshot):
        try:
            # Checking whether nfs/smb share created from fs_snapshot
            if self.is_snap_has_share(fs_snapshot):
                msg = "Filesystem snapshot cannot be deleted because it has " \
                      "nfs/smb share"
                LOG.error(msg)
                self.module.fail_json(msg=msg)
            fs_snapshot.delete()
            return None

        except Exception as e:
            error_msg = "Failed to delete filesystem snapshot" \
                        " [name: %s, id: %s] with error %s." \
                        % (fs_snapshot.name, fs_snapshot.id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_fs_snapshot_obj(self, name=None, id=None):
        fs_snapshot = id if id else name
        msg = "Failed to get details of filesystem snapshot %s with error %s."
        try:
            fs_snap_obj = self.unity_conn.get_snap(name=name, _id=id)
            if fs_snap_obj and fs_snap_obj.existed:
                LOG.info("Successfully got the filesystem snapshot object "
                         "%s.", fs_snap_obj)
            else:
                fs_snap_obj = None
            return fs_snap_obj

        except utils.HttpError as e:
            if e.http_status == 401:
                cred_err = ("Incorrect username or password , %s" % e.message)
                self.module.fail_json(msg=cred_err)
            else:
                err_msg = msg % (fs_snapshot, str(e))
                LOG.error(err_msg)
                self.module.fail_json(msg=err_msg)

        except utils.UnityResourceNotFoundError as e:
            err_msg = msg % (fs_snapshot, str(e))
            LOG.error(err_msg)
            return None

        except Exception as e:
            err_msg = msg % (fs_snapshot, str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def get_filesystem_obj(self, nas_server=None, name=None, id=None):
        filesystem = id if id else name
        try:
            obj_fs = None
            if name:
                if not nas_server:
                    err_msg = "NAS Server is required to get the FileSystem."
                    LOG.error(err_msg)
                    self.module.fail_json(msg=err_msg)
                obj_fs = self.unity_conn.get_filesystem(name=name,
                                                        nas_server=nas_server)
                if obj_fs and obj_fs.existed:
                    LOG.info("Successfully got the filesystem object %s.",
                             obj_fs)
                    return obj_fs
            if id:
                if nas_server:
                    obj_fs = self.unity_conn\
                        .get_filesystem(id=id, nas_server=nas_server)
                else:
                    obj_fs = self.unity_conn.get_filesystem(id=id)
                if obj_fs and obj_fs.existed:
                    LOG.info("Successfully got the filesystem object %s.",
                             obj_fs)
                    return obj_fs
        except Exception as e:
            error_msg = "Failed to get filesystem %s with error %s."\
                        % (filesystem, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_nas_server_obj(self, name=None, id=None):
        nas_server = id if id else name
        error_msg = ("Failed to get NAS server %s." % nas_server)
        try:
            obj_nas = self.unity_conn.get_nas_server(_id=id, name=name)
            if (name and obj_nas.existed) or (id and obj_nas.existed):
                LOG.info("Successfully got the NAS server object %s.",
                         obj_nas)
                return obj_nas
            else:
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)
        except Exception as e:
            error_msg = "Failed to get NAS server %s with error %s."\
                        % (nas_server, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def create_fs_snapshot_details_dict(self, fs_snapshot):
        """ Add name and id of storage resource to filesystem snapshot
            details """

        snapshot_dict = fs_snapshot._get_properties()
        del snapshot_dict['storage_resource']

        snapshot_dict['filesystem_name'] = fs_snapshot.storage_resource.name
        snapshot_dict['filesystem_id'] = fs_snapshot.storage_resource.filesystem.id

        obj_fs = self.unity_conn.\
            get_filesystem(id=fs_snapshot.storage_resource.filesystem.id)
        if obj_fs and obj_fs.existed:
            snapshot_dict['nas_server_name'] = obj_fs.nas_server[0].name
            snapshot_dict['nas_server_id'] = obj_fs.nas_server[0].id

        return snapshot_dict

    def perform_module_operation(self):
        """
        Perform different actions on snapshot module based on parameters
        chosen in playbook
        """
        snapshot_name = self.module.params['snapshot_name']
        snapshot_id = self.module.params['snapshot_id']
        filesystem_name = self.module.params['filesystem_name']
        filesystem_id = self.module.params['filesystem_id']
        nas_server_name = self.module.params['nas_server_name']
        nas_server_id = self.module.params['nas_server_id']
        auto_delete = self.module.params['auto_delete']
        expiry_time = self.module.params['expiry_time']
        description = self.module.params['description']
        fs_access_type = self.module.params['fs_access_type']
        state = self.module.params['state']
        nas_server_resource = None
        filesystem_resource = None
        changed = False

        LOG.info("Getting Filesystem Snapshot details.")
        fs_snapshot = self.get_fs_snapshot_obj(name=snapshot_name,
                                               id=snapshot_id)

        msg = "Filesystem Snapshot details: %s." % str(fs_snapshot)
        LOG.info(msg)

        # Get NAS server Object
        if nas_server_name is not None:
            if nas_server_name == "" or nas_server_name.isspace():
                self.module.fail_json(msg="Invalid nas_server_name given,"
                                          " Please provide a valid name.")
            nas_server_resource = self\
                .get_nas_server_obj(name=nas_server_name)
        elif nas_server_id is not None:
            if nas_server_id == "" or nas_server_id.isspace():
                self.module.fail_json(msg="Invalid nas_server_id given,"
                                          " Please provide a valid ID.")
            nas_server_resource = self.get_nas_server_obj(id=nas_server_id)

        #  Get Filesystem Object
        if filesystem_name is not None:
            if filesystem_name == "" or filesystem_name.isspace():
                self.module.fail_json(msg="Invalid filesystem_name given,"
                                          " Please provide a valid name.")
            filesystem_resource = self\
                .get_filesystem_obj(nas_server=nas_server_resource,
                                    name=filesystem_name)
            fs_res_id = filesystem_resource.storage_resource.id
        elif filesystem_id is not None:
            if filesystem_id == "" or filesystem_id.isspace():
                self.module.fail_json(msg="Invalid filesystem_id given,"
                                          " Please provide a valid ID.")
            filesystem_resource = self\
                .get_filesystem_obj(id=filesystem_id)
            fs_res_id = filesystem_resource[0].storage_resource.id

        # Check for error, if user tries to create a filesystem snapshot
        # with the same name.
        if fs_snapshot and filesystem_resource and \
            (fs_snapshot.storage_resource.id
             != fs_res_id):
            self.module.fail_json(
                msg="Snapshot %s is of %s storage resource. Cannot create new"
                    " snapshot with same name for %s storage resource."
                    % (fs_snapshot.name, fs_snapshot.storage_resource.name,
                       filesystem_resource.storage_resource.name))

        # check for valid expiry_time
        if expiry_time is not None and \
                (expiry_time == "" or expiry_time.isspace()):
            self.module.fail_json(msg="Please provide valid expiry_time,"
                                      " empty expiry_time given.")
        if expiry_time:
            self.validate_expiry_time(expiry_time)

        # Check if in input auto_delete is True and expiry_time is not None
        if expiry_time and auto_delete:
            error_msg = "Cannot set expiry_time if auto_delete given as True."
            LOG.info(error_msg)
            self.module.fail_json(msg=error_msg)

        # check for fs_access_type
        if fs_access_type is not None:
            if (fs_access_type == "" or fs_access_type.isspace()):
                self.module.fail_json(msg="Please provide valid "
                                          "fs_access_type, empty "
                                          "fs_access_type given.")
            if fs_access_type == "Checkpoint":
                fs_access_type = utils.FilesystemSnapAccessTypeEnum.CHECKPOINT
            elif fs_access_type == "Protocol":
                fs_access_type = utils.FilesystemSnapAccessTypeEnum.PROTOCOL

        # Check whether to modify the filesystem snapshot or not
        fs_snap_modify_dict = dict()
        if state == 'present' and fs_snapshot:
            fs_snap_modify_dict = self\
                .to_update(fs_snapshot, description=description,
                           auto_del=auto_delete, expiry_time=expiry_time,
                           fs_access_type=fs_access_type)

        # Create Filesystem Snapshot
        if not fs_snapshot and state == "present":
            LOG.info("Creating the filesystem snapshot.")

            if snapshot_id:
                self.module.fail_json(msg="Creation of Filesystem Snapshot is"
                                          " allowed using snapshot_name only,"
                                          " snapshot_id given.")
            if snapshot_name == "" or snapshot_name.isspace():
                self.module.fail_json(msg="snapshot_name is required for"
                                          " creation of the filesystem"
                                          " snapshot, empty snapshot_name"
                                          " given.")
            if not filesystem_resource:
                self.module.fail_json(msg="filesystem_name or filesystem_id"
                                          " required to create a snapshot.")

            fs_snapshot = self.create_filesystem_snapshot(
                snapshot_name,
                fs_res_id,
                description,
                auto_delete,
                expiry_time,
                fs_access_type)
            changed = True

        # Update the Snapshot
        if fs_snapshot and state == "present" and fs_snap_modify_dict:
            LOG.info("Updating the Filesystem Snapshot.")
            self.update_filesystem_snapshot(fs_snapshot, fs_snap_modify_dict)
            changed = True

        # Delete the Filesystem Snapshot
        if state == "absent" and fs_snapshot:
            fs_snapshot = self.delete_fs_snapshot(fs_snapshot)
            changed = True

        # Add filesystem snapshot details to the result.
        if fs_snapshot:
            fs_snapshot.update()
            self.result["filesystem_snapshot_details"] = \
                self.create_fs_snapshot_details_dict(fs_snapshot)
        else:
            self.result["filesystem_snapshot_details"] = {}

        self.result["changed"] = changed
        self.module.exit_json(**self.result)


def to_update_expiry_time(fs_snapshot, expiry_time=None):
    """ Check whether to update expiry_time or not"""
    if not expiry_time:
        return False
    if fs_snapshot.expiration_time is None:
        return True
    if convert_timestamp_to_sec(expiry_time, fs_snapshot.expiration_time)\
            != 0:
        return True
    return False


def convert_timestamp_to_sec(expiry_time, snap_time):
    """Converts the time difference to seconds"""
    snap_time_str = snap_time.strftime('%m/%d/%Y %H:%M')
    snap_timestamp = datetime.strptime(snap_time_str, '%m/%d/%Y %H:%M')
    expiry_timestamp = datetime.strptime(expiry_time, "%m/%d/%Y %H:%M")
    return int((expiry_timestamp - snap_timestamp).total_seconds())


def get_snapshot_parameters():
    """This method provide parameter required for the ansible filesystem
    snapshot module on Unity"""
    return dict(
        snapshot_name=dict(required=False, type='str'),
        snapshot_id=dict(required=False, type='str'),
        filesystem_name=dict(required=False, type='str'),
        filesystem_id=dict(required=False, type='str'),
        nas_server_name=dict(required=False, type='str'),
        nas_server_id=dict(required=False, type='str'),
        auto_delete=dict(required=False, type='bool'),
        expiry_time=dict(required=False, type='str'),
        description=dict(required=False, type='str'),
        fs_access_type=dict(required=False, type='str',
                            choices=['Checkpoint', 'Protocol']),
        state=dict(required=True, type='str', choices=['present', 'absent'])
    )


def main():
    """ Create Unity Filesystem Snapshot object and perform actions on it
        based on user input from playbook"""
    obj = FilesystemSnapshot()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
