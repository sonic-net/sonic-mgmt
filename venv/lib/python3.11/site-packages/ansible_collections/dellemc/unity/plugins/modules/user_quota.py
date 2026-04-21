#!/usr/bin/python
# Copyright: (c) 2021-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing User Quota on Unity"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: user_quota
short_description: Manage user quota on the Unity storage system
description:
- Managing User Quota on the Unity storage system includes
  Create user quota,
  Get user quota,
  Modify user quota,
  Delete user quota,
  Create user quota for quota tree,
  Modify user quota for quota tree and
  Delete user quota for quota tree.
version_added: '1.2.0'
extends_documentation_fragment:
  - dellemc.unity.unity
author:
- Spandita Panigrahi (@panigs7) <ansible.team@dell.com>
options:
  filesystem_name:
    description:
    - The name of the filesystem for which the user quota is created.
    - For creation of a user quota either I(filesystem_name) or
      I(filesystem_id) is required.
    type: str
  filesystem_id:
    description:
    - The ID of the filesystem for which the user quota is created.
    - For creation of a user quota either I(filesystem_id) or
      I(filesystem_name) is required.
    type: str
  nas_server_name:
    description:
    - The name of the NAS server in which the filesystem is created.
    - For creation of a user quota either I(nas_server_name) or
      I(nas_server_id) is required.
    type: str
  nas_server_id:
    description:
    - The ID of the NAS server in which the filesystem is created.
    - For creation of a user quota either I(filesystem_id) or
      I(filesystem_name) is required.
    type: str
  hard_limit:
    description:
    - Hard limitation for a user on the total space available. If exceeded, user cannot write data.
    - Value C(0) implies no limit.
    - One of the values of I(soft_limit) and I(hard_limit) can be C(0), however, both cannot be C(0)
      during creation or modification of user quota.
    type: int
  soft_limit:
    description:
    - Soft limitation for a user on the total space available. If exceeded,
      notification will be sent to the user for the grace period mentioned, beyond
      which the user cannot use space.
    - Value C(0) implies no limit.
    - Both I(soft_limit) and I(hard_limit) cannot be C(0) during creation or modification
      of user quota.
    type: int
  cap_unit:
    description:
    - Unit of I(soft_limit) and I(hard_limit) size.
    - It defaults to C(GB) if not specified.
    choices: ['MB', 'GB', 'TB']
    type: str
  user_type:
    description:
    - Type of user creating a user quota.
    - Mandatory while creating or modifying user quota.
    choices: ['Unix', 'Windows']
    type: str
  win_domain:
    description:
    - Fully qualified or short domain name for Windows user type.
    - Mandatory when I(user_type) is C(Windows).
    type: str
  user_name:
    description:
    - User name of the user quota when I(user_type) is C(Windows) or C(Unix).
    - Option I(user_name) must be specified along with I(win_domain) when I(user_type) is C(Windows).
    type: str
  uid:
    description:
    - User ID of the user quota.
    type: str
  user_quota_id:
    description:
    - User quota ID generated after creation of a user quota.
    type: str
  tree_quota_id:
    description:
    - The ID of the quota tree.
    - Either I(tree_quota_id) or I(path) to quota tree is required to
      create/modify/delete user quota for a quota tree.
    type: str
  path:
    description:
    - The path to the quota tree.
    - Either I(tree_quota_id) or I(path) to quota tree is required to
      create/modify/delete user quota for a quota tree.
    - Path must start with a forward slash '/'.
    type: str
  state:
    description:
    - The I(state) option is used to mention the existence of the user quota.
    type: str
    required: true
    choices: ['absent', 'present']

notes:
  - The I(check_mode) is not supported.
'''

EXAMPLES = r'''
- name: Get user quota details by user quota id
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    user_quota_id: "userquota_171798700679_0_123"
    state: "present"

- name: Get user quota details by user quota uid/user name
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_name: "fs_2171"
    nas_server_id: "nas_21"
    user_name: "test"
    state: "present"

- name: Create user quota for a filesystem with filesystem id
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "fs_2171"
    hard_limit: 6
    cap_unit: "TB"
    soft_limit: 5
    uid: "111"
    state: "present"

- name: Create user quota for a filesystem with filesystem name
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_name: "Test_filesystem"
    nas_server_name: "lglad068"
    hard_limit: 6
    cap_unit: "TB"
    soft_limit: 5
    uid: "111"
    state: "present"

- name: Modify user quota limit usage by user quota id
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    user_quota_id: "userquota_171798700679_0_123"
    hard_limit: 10
    cap_unit: "TB"
    soft_limit: 8
    state: "present"

- name: Modify user quota by filesystem id and user quota uid/user_name
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "fs_2171"
    user_type: "Windows"
    win_domain: "prod"
    user_name: "sample"
    hard_limit: 12
    cap_unit: "TB"
    soft_limit: 10
    state: "present"

- name: Delete user quota
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "fs_2171"
    win_domain: "prod"
    user_name: "sample"
    state: "absent"

- name: Create user quota of a quota tree
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    tree_quota_id: "treequota_171798700679_4"
    user_type: "Windows"
    win_domain: "prod"
    user_name: "sample"
    soft_limit: 9
    cap_unit: "TB"
    state: "present"

- name: Create user quota of a quota tree by quota tree path
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "fs_2171"
    path: "/sample"
    user_type: "Unix"
    user_name: "test"
    hard_limit: 2
    cap_unit: "TB"
    state: "present"

- name: Modify user quota of a quota tree
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    tree_quota_id: "treequota_171798700679_4"
    user_type: "Windows"
    win_domain: "prod"
    user_name: "sample"
    soft_limit: 10
    cap_unit: "TB"
    state: "present"

- name: Modify user quota of a quota tree by quota tree path
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "fs_2171"
    path: "/sample"
    user_type: "Windows"
    win_domain: "prod"
    user_name: "sample"
    hard_limit: 12
    cap_unit: "TB"
    state: "present"

- name: Delete user quota of a quota tree by quota tree path
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "fs_2171"
    path: "/sample"
    win_domain: "prod"
    user_name: "sample"
    state: "absent"

- name: Delete user quota of a quota tree by quota tree id
  user_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    tree_quota_id: "treequota_171798700679_4"
    win_domain: "prod"
    user_name: "sample"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true

get_user_quota_details:
    description: Details of the user quota.
    returned: When user quota exists
    type: dict
    contains:
        filesystem:
            description: Filesystem details for which the user quota is
                         created.
            type: dict
            contains:
                UnityFileSystem:
                    description: Filesystem details for which the
                                user quota is created.
                    type: dict
                    contains:
                        id:
                            description: ID of the filesystem for
                                         which the user quota is created.
                            type: str
                        name:
                            description: Name of filesystem.
                            type: str
                        nas_server:
                            description: Nasserver details where
                                         filesystem is created.
                            type: dict
                            contains:
                                name:
                                    description: Name of nasserver.
                                    type: str
                                id:
                                    description: ID of nasserver.
                                    type: str
        tree_quota:
            description: Quota tree details for which the user quota is
                         created.
            type: dict
            contains:
                UnityTreeQuota:
                    description: Quota tree details for which the user
                                 quota is created.
                    type: dict
                    contains:
                        id:
                            description: ID of the quota tree.
                            type: str
                        path:
                            description: Path to quota tree.
                            type: str
        gp_left:
            description: The grace period left after the soft limit
                         for the user quota is exceeded.
            type: int
        hard_limit:
            description: Hard limitation for a user on the total space
                         available. If exceeded, user cannot write data.
            type: int
        hard_ratio:
            description: The hard ratio is the ratio between the
                         hard limit size of the user quota
                         and the amount of storage actually consumed.
            type: str
        soft_limit:
            description: Soft limitation for a user on the total space
                         available. If exceeded, notification will be
                         sent to user for the grace period mentioned, beyond
                         which user cannot use space.
            type: int
        soft_ratio:
            description: The soft ratio is the ratio between
                         the soft limit size of the user quota
                         and the amount of storage actually consumed.
            type: str
        id:
            description: User quota ID.
            type: str
        size_used:
            description: Size of used space in the filesystem
                         by the user files.
            type: int
        state:
            description: State of the user quota.
            type: int
        uid:
            description: User ID of the user.
            type: int
        unix_name:
            description: Unix user name for this user quota's uid.
            type: str
        windows_names:
            description: Windows user name that maps to this quota's uid.
            type: str
        windows_sids:
            description: Windows SIDs that maps to this quota's uid
            type: str
    sample: {
        "existed": true,
        "filesystem": {
            "UnityFileSystem": {
                "hash": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
                "id": "fs_120",
                "name": "nfs-multiprotocol",
                "nas_server": {
                    "id": "nas_1",
                    "name": "lglad072"
                }
            }
        },
        "gp_left": null,
        "hard_limit": "10.0 GB",
        "hard_ratio": null,
        "hash": 8752448438089,
        "id": "userquota_171798694698_0_60000",
        "size_used": 0,
        "soft_limit": "10.0 GB",
        "soft_ratio": null,
        "state": 0,
        "tree_quota": null,
        "uid": 60000,
        "unix_name": null,
        "windows_names": null,
        "windows_sids": null
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('user_quota')

application_type = "Ansible/1.7.1"


class UserQuota(object):
    """Class with User Quota operations"""

    def __init__(self):
        """Define all parameters required by this module"""
        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_user_quota_parameters())

        mutually_exclusive = [['user_name', 'uid'], ['uid', 'win_domain'],
                              ['filesystem_name', 'filesystem_id'],
                              ['nas_server_name', 'nas_server_id'],
                              ['user_name', 'user_quota_id'],
                              ['uid', 'user_quota_id']]

        required_if = [('user_type', 'Windows', ['win_domain', 'user_name'], False),
                       ('user_type', 'Unix', ['user_name'], False)]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=False,
            mutually_exclusive=mutually_exclusive,
            required_if=required_if)
        utils.ensure_required_libs(self.module)

        self.unity_conn = utils.get_unity_unisphere_connection(
            self.module.params, application_type)

    def check_user_is_present(self, fs_id, uid, unix, win_name, user_quota_id):
        """
            Check if user quota is present in filesystem.
            :param fs_id: ID of filesystem where user quota is searched.
            :param uid: UID of the user quota
            :param unix: Unix user name of user quota
            :param win_name: Windows user name of user quota
            :param user_quota_id: ID of the user quota
            :return: ID of user quota if it exists else None.
        """

        if not self.check_user_type_provided(win_name, uid, unix):
            return None

        user_name_or_uid_or_id = unix if unix else win_name if win_name else uid if \
            uid else user_quota_id

        # All user quotas in the given filesystem
        all_user_quota = self.unity_conn.get_user_quota(filesystem=fs_id, id=user_quota_id,
                                                        unix_name=unix, windows_names=win_name,
                                                        uid=uid)

        for user_quota in range(len(all_user_quota)):

            if all_user_quota[user_quota].tree_quota is None:
                msg = "User quota %s with id %s " \
                      "is present in filesystem %s" \
                      % (user_name_or_uid_or_id, all_user_quota[user_quota].id, fs_id)
                LOG.info(msg)
                return all_user_quota[user_quota].id

        return None

    def check_quota_tree_is_present(self, fs_id, path, tree_quota_id):
        """
            Check if quota tree is present in filesystem.
            :param fs_id: ID of filesystem where quota tree is searched.
            :param path: Path to quota tree
            :param tree_quota_id: ID of the quota tree
            :return: ID of quota tree if it exists.
        """

        path_or_id = path if path else tree_quota_id
        tree_quota_obj = self.unity_conn.get_tree_quota(filesystem=fs_id, path=path,
                                                        id=tree_quota_id)
        if len(tree_quota_obj) > 0:
            msg = "Tree quota id %s present in filesystem %s" % (tree_quota_obj[0].id, fs_id)
            LOG.info(msg)
            return tree_quota_obj[0].id
        else:
            errormsg = "The quota tree '%s' does not exist" % path_or_id
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def check_user_quota_in_quota_tree(self, tree_quota_id, uid, unix, win_name, user_quota_id):
        """
            Check if user quota is present in quota tree.
            :param tree_quota_id: ID of quota tree where user quota is searched.
            :param uid: UID of user quota
            :param unix: Unix name of user quota
            :param win_name: Windows name of user quota
            :param user_quota_id: ID of the user quota
            :return: ID of user quota if it exists in quota tree else None.
        """
        if not self.check_user_type_provided(win_name, uid, unix):
            return None

        user_quota_name = uid if uid else unix if unix else win_name \
            if win_name else user_quota_id
        user_quota_obj = self.unity_conn.get_user_quota(tree_quota=tree_quota_id,
                                                        uid=uid, windows_names=win_name,
                                                        unix_name=unix,
                                                        id=user_quota_id)
        if len(user_quota_obj) > 0:
            msg = "User quota %s is present in quota tree %s " % (user_quota_name, tree_quota_id)
            LOG.info(msg)
            return user_quota_obj[0].id
        else:
            return None

    def create_user_quota(self, fs_id, soft_limit, hard_limit, unit, uid, unix, win_name, tree_quota_id):
        """
            Create user quota of a filesystem.
            :param fs_id: ID of filesystem where user quota is to be created.
            :param soft_limit: Soft limit
            :param hard_limit: Hard limit
            :param unit: Unit of soft limit and hard limit
            :param uid: UID of the user quota
            :param unix: Unix user name of user quota
            :param win_name: Windows user name of user quota
            :param tree_quota_id: ID of tree quota
            :return: Object containing new user quota details.
        """

        unix_or_uid_or_win = uid if uid else unix if unix else win_name
        fs_id_or_tree_quota_id = fs_id if fs_id else tree_quota_id
        if soft_limit is None and hard_limit is None:
            errormsg = "Both soft limit and hard limit cannot be empty. " \
                       "Please provide atleast one to create user quota."
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

        soft_limit_in_bytes = utils.get_size_bytes(soft_limit, unit)
        hard_limit_in_bytes = utils.get_size_bytes(hard_limit, unit)
        try:
            if self.check_user_type_provided(win_name, uid, unix):
                obj_user_quota = self.unity_conn.create_user_quota(filesystem_id=fs_id,
                                                                   hard_limit=hard_limit_in_bytes,
                                                                   soft_limit=soft_limit_in_bytes,
                                                                   uid=uid, unix_name=unix,
                                                                   win_name=win_name,
                                                                   tree_quota_id=tree_quota_id)
                LOG.info("Successfully created user quota")
                return obj_user_quota

        except Exception as e:
            errormsg = "Create quota for user {0} on {1} , failed with error {2} "\
                .format(unix_or_uid_or_win, fs_id_or_tree_quota_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_filesystem_user_quota_display_attributes(self, user_quota_id):
        """Get display user quota attributes
            :param user_quota_id: User quota ID
            :return: User quota dict to display
        """
        try:
            user_quota_obj = self.unity_conn.get_user_quota(user_quota_id)
            user_quota_details = user_quota_obj._get_properties()

            if user_quota_obj and user_quota_obj.existed:
                user_quota_details['soft_limit'] = utils. \
                    convert_size_with_unit(int(user_quota_details['soft_limit']))
                user_quota_details['hard_limit'] = utils. \
                    convert_size_with_unit(int(user_quota_details['hard_limit']))

                user_quota_details['filesystem']['UnityFileSystem']['name'] = \
                    user_quota_obj.filesystem.name
                user_quota_details['filesystem']['UnityFileSystem'].update(
                    {'nas_server': {'name': user_quota_obj.filesystem.nas_server.name,
                                    'id': user_quota_obj.filesystem.nas_server.id}})

                if user_quota_obj.tree_quota:
                    user_quota_details['tree_quota']['UnityTreeQuota']['path'] = \
                        user_quota_obj.tree_quota.path

                return user_quota_details
            else:
                errormsg = "User quota does not exist."
                LOG.error(errormsg)
                self.module.fail_json(msg=errormsg)

        except Exception as e:
            errormsg = "Failed to display the details of user quota {0} with " \
                       "error {1}".format(user_quota_obj.id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_filesystem(self, nas_server=None, name=None, id=None):
        """
            Get filesystem details.
            :param nas_server: Nas server object.
            :param name: Name of filesystem.
            :param id: ID of filesystem.
            :return: Object containing filesystem details if it exists.
        """
        id_or_name = id if id else name
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
                    obj_fs = self.unity_conn \
                        .get_filesystem(id=id, nas_server=nas_server)
                else:
                    obj_fs = self.unity_conn.get_filesystem(id=id)
                if obj_fs and obj_fs.existed:
                    LOG.info("Successfully got the filesystem object %s.",
                             obj_fs)
                    return obj_fs
        except Exception as e:
            error_msg = "Failed to get filesystem %s with error %s." \
                        % (id_or_name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_nas_server_obj(self, name=None, id=None):
        """
            Get nas server details.
            :param name: Nas server name.
            :param id: Nas server ID.
            :return: Object containing nas server details if it exists.
        """
        nas_server = id if id else name
        error_msg = ("Failed to get NAS server %s." % nas_server)
        try:
            obj_nas = self.unity_conn.get_nas_server(_id=id, name=name)
            if name and obj_nas.existed:
                LOG.info("Successfully got the NAS server object %s.",
                         obj_nas)
                return obj_nas
            elif id and obj_nas.existed:
                LOG.info("Successfully got the NAS server object %s.",
                         obj_nas)
                return obj_nas
            else:
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)
        except Exception as e:
            error_msg = "Failed to get NAS server %s with error %s." \
                        % (nas_server, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def modify_user_quota(self, user_quota_id, soft_limit, hard_limit, unit):
        """
            Modify user quota of filesystem by its uid/username/user quota id.
            :param user_quota_id: ID of the user quota
            :param soft_limit: Soft limit
            :param hard_limit: Hard limit
            :param unit: Unit of soft limit and hard limit
            :return: Boolean value whether modify user quota operation is successful.
        """

        if soft_limit is None and hard_limit is None:
            return False

        user_quota_obj = self.unity_conn.get_user_quota(user_quota_id)._get_properties()

        if soft_limit is None:
            soft_limit_in_bytes = user_quota_obj['soft_limit']
        else:
            soft_limit_in_bytes = utils.get_size_bytes(soft_limit, unit)

        if hard_limit is None:
            hard_limit_in_bytes = user_quota_obj['hard_limit']
        else:
            hard_limit_in_bytes = utils.get_size_bytes(hard_limit, unit)

        if user_quota_obj:
            if user_quota_obj['soft_limit'] == soft_limit_in_bytes and \
                    user_quota_obj['hard_limit'] == hard_limit_in_bytes:
                return False
        else:
            error_msg = "The user quota does not exist."
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

        try:
            obj_user_quota = self.unity_conn.modify_user_quota(user_quota_id=user_quota_id,
                                                               hard_limit=hard_limit_in_bytes,
                                                               soft_limit=soft_limit_in_bytes)
            LOG.info("Successfully modified user quota")
            if obj_user_quota:
                return True
        except Exception as e:
            errormsg = "Modify user quota {0} failed" \
                       " with error {1}".format(user_quota_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def check_user_type_provided(self, win_name, uid, unix_name):
        """Checks if user type or uid is provided
           :param win_name: Windows name of user quota
           :param uid: UID of user quota
           :param unix_name: Unix name of user quota"""
        if win_name is None and uid is None and unix_name is None:
            return False
        else:
            return True

    def perform_module_operation(self):
        """
        Perform different actions on user quota module based on parameters
        passed in the playbook
        """
        filesystem_id = self.module.params['filesystem_id']
        filesystem_name = self.module.params['filesystem_name']
        nas_server_name = self.module.params['nas_server_name']
        nas_server_id = self.module.params['nas_server_id']
        cap_unit = self.module.params['cap_unit']
        state = self.module.params['state']
        user_quota_id = self.module.params['user_quota_id']
        hard_limit = self.module.params['hard_limit']
        soft_limit = self.module.params['soft_limit']
        user_type = self.module.params['user_type']
        uid = self.module.params['uid']
        user_name = self.module.params['user_name']
        win_domain = self.module.params['win_domain']
        tree_quota_id = self.module.params['tree_quota_id']
        path = self.module.params['path']
        create_user_quota_obj = None
        win_name = None
        unix_name = None
        nas_server_resource = None
        fs_id = None
        user_quota_details = ''
        filesystem_obj = None

        '''
        result is a dictionary to contain end state and user quota details
        '''
        result = dict(
            changed=False,
            create_user_quota=False,
            modify_user_quota=False,
            get_user_quota_details={},
            delete_user_quota=False
        )

        if (soft_limit or hard_limit) and cap_unit is None:
            cap_unit = 'GB'

        if soft_limit == 0 and hard_limit == 0:
            error_message = 'Both soft limit and hard limit cannot be unlimited'
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

        if soft_limit and utils.is_size_negative(soft_limit):
            error_message = "Invalid soft_limit provided, " \
                            "must be greater than 0"
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

        if hard_limit and utils.is_size_negative(hard_limit):
            error_message = "Invalid hard_limit provided, " \
                            "must be greater than 0"
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

        if (user_type or uid) and filesystem_id is None and \
                filesystem_name is None and tree_quota_id is None:
            error_message = 'Please provide either ' \
                            'filesystem_name or filesystem_id'
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

        if (nas_server_name or nas_server_id) \
                and (filesystem_id is None and filesystem_name is None):
            error_message = 'Please provide either ' \
                            'filesystem_name or filesystem_id'
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

        '''
        Validate path to quota tree
        '''
        if path is not None:
            if utils.is_input_empty(path):
                self.module.fail_json(msg=" Please provide a valid path.")
            elif not path.startswith('/'):
                self.module.fail_json(msg="The path is relative to the root of the file system "
                                          "and must start with a forward slash.")

            if filesystem_id is None and filesystem_name is None:
                self.module.fail_json(msg="Please provide either filesystem_name or fileystem_id.")

        if user_type and filesystem_id is None and filesystem_name is None and tree_quota_id is None:
            error_message = 'Please provide either ' \
                            'filesystem_name or filesystem_id to create user quota for a' \
                            'filesystem. Or provide tree_quota_id to create user quota for a quota tree.'
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

        '''
        Get NAS server Object
        '''

        if nas_server_name is not None:
            if utils.is_input_empty(nas_server_name):
                self.module.fail_json(msg="Invalid nas_server_name given,"
                                          " Please provide a valid name.")
            nas_server_resource = self \
                .get_nas_server_obj(name=nas_server_name)
        elif nas_server_id is not None:
            if utils.is_input_empty(nas_server_id):
                self.module.fail_json(msg="Invalid nas_server_id given,"
                                          " Please provide a valid ID.")
            nas_server_resource = self.get_nas_server_obj(id=nas_server_id)

        '''
            Get filesystem Object
        '''
        if filesystem_name is not None:
            if utils.is_input_empty(filesystem_name):
                self.module.fail_json(msg="Invalid filesystem_name given,"
                                          " Please provide a valid name.")
            filesystem_obj = self \
                .get_filesystem(nas_server=nas_server_resource,
                                name=filesystem_name)
            fs_id = filesystem_obj.id
        elif filesystem_id is not None:
            if utils.is_input_empty(filesystem_id):
                self.module.fail_json(msg="Invalid filesystem_id given,"
                                          " Please provide a valid ID.")
            filesystem_obj = self \
                .get_filesystem(id=filesystem_id)
            if filesystem_obj:
                filesystem_obj = filesystem_obj[0]
                fs_id = filesystem_obj.id
            else:
                self.module.fail_json(msg="Filesystem does not exist.")

        if (user_name or win_domain) and (soft_limit or hard_limit) \
                and user_type is None:
            self.module.fail_json(msg="Invalid user_type given,"
                                      " Please provide a valid user_type.")

        # Check the sharing protocol supported by the filesystem
        # while creating a user quota
        if filesystem_obj and (soft_limit is not None or hard_limit is not None):
            supported_protocol = filesystem_obj.supported_protocols

            if supported_protocol == utils.FSSupportedProtocolEnum["CIFS"] \
                    and (user_type == "Unix" or uid):
                self.module.fail_json(msg="This filesystem supports only SMB protocol "
                                          "and applicable only for windows users. "
                                          "Please provide valid windows details.")
            elif supported_protocol == utils.FSSupportedProtocolEnum["NFS"] \
                    and user_type == "Windows":
                self.module.fail_json(msg="This filesystem supports only NFS protocol "
                                          "and applicable only for unix users. "
                                          "Please provide valid uid or unix details.")

        '''
        Validate user type or uid
        '''
        if uid and (utils.is_input_empty(uid) or not uid.isnumeric()):
            self.module.fail_json(msg=" UID is empty. Please provide valid UID.")
        if user_type:
            if user_type == "Unix":
                if user_name is None or utils.is_input_empty(user_name):
                    self.module.fail_json(msg=" 'user_name' is empty. Please provide valid user_name.")

            if user_type == "Windows":
                if win_domain is None or utils.is_input_empty(win_domain):
                    self.module.fail_json(msg=" 'win_domain' is empty. Please provide valid win_domain.")
                elif user_name is None or utils.is_input_empty(user_name):
                    self.module.fail_json(msg=" 'user_name' is empty. Please provide valid user_name.")

        if user_type != "Unix" and win_domain:
            win_domain = win_domain.replace(".com", "")
            win_name = win_domain + '\\' + user_name

        if win_name is None and user_name:
            unix_name = user_name

        '''
        Check if quota tree is already present in the filesystem
        '''
        if tree_quota_id or path:
            quota_tree_id_present = self.check_quota_tree_is_present(fs_id, path, tree_quota_id)
            tree_quota_id = quota_tree_id_present

        '''
        Check if the user quota is already present in the filesystem/ quota tree
        '''
        if tree_quota_id:
            user_id_present = self.check_user_quota_in_quota_tree(tree_quota_id, uid, unix_name, win_name,
                                                                  user_quota_id)
            fs_id = None if tree_quota_id is not None else fs_id
        else:
            user_id_present = self.check_user_is_present(fs_id, uid, unix_name, win_name, user_quota_id)

        if user_id_present:
            user_quota_id = user_id_present

        if state == "present":
            if user_quota_id:
                # Modify user quota. If no change modify_user_quota is false.
                result['modify_user_quota'] = self.modify_user_quota(user_quota_id, soft_limit,
                                                                     hard_limit, cap_unit)

            else:
                LOG.info("Creating user quota")
                create_user_quota_obj = self.create_user_quota(fs_id, soft_limit, hard_limit,
                                                               cap_unit, uid, unix_name, win_name,
                                                               tree_quota_id)
                if create_user_quota_obj:
                    user_quota_id = create_user_quota_obj.id
                    result['create_user_quota'] = True
                else:
                    user_quota_id = None
        '''
        Deleting user quota.
        When both soft limit and hard limit are set to 0, it implies the user quota has
        unlimited quota. Thereby, Unity removes the user quota id.
        '''

        if state == "absent" and user_quota_id:
            soft_limit = 0
            hard_limit = 0
            err_msg = "Deleting user quota %s" % user_quota_id
            LOG.info(err_msg)
            result['delete_user_quota'] = self.modify_user_quota(user_quota_id,
                                                                 soft_limit, hard_limit, cap_unit)
        '''
        Get user details
        '''

        if state == "present" and user_quota_id:
            user_quota_details = self.get_filesystem_user_quota_display_attributes(user_quota_id)

        result['get_user_quota_details'] = user_quota_details
        if result['create_user_quota'] or result['modify_user_quota'] or result['delete_user_quota']:
            result['changed'] = True

        self.module.exit_json(**result)


def get_user_quota_parameters():
    """This method provide parameters required for the ansible filesystem
       user quota module on Unity"""
    return dict(
        filesystem_id=dict(required=False, type='str'),
        filesystem_name=dict(required=False, type='str'),
        state=dict(required=True, type='str', choices=['present', 'absent']),
        user_type=dict(required=False, type='str',
                       choices=['Windows', 'Unix']),
        user_name=dict(required=False, type='str'),
        uid=dict(required=False, type='str'),
        win_domain=dict(required=False, type='str'),
        hard_limit=dict(required=False, type='int'),
        soft_limit=dict(required=False, type='int'),
        cap_unit=dict(required=False, type='str', choices=['MB', 'GB', 'TB']),
        user_quota_id=dict(required=False, type='str'),
        nas_server_name=dict(required=False, type='str'),
        nas_server_id=dict(required=False, type='str'),
        tree_quota_id=dict(required=False, type='str'),
        path=dict(required=False, type='str', no_log=True)
    )


def main():
    """ Create Unity user quota object and perform action on it
        based on user input from playbook"""
    obj = UserQuota()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
