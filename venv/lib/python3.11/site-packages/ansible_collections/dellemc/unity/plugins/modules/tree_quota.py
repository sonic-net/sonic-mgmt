#!/usr/bin/python
# Copyright: (c) 2021-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt))

"""Ansible module for managing quota tree on Unity"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: tree_quota
short_description: Manage quota tree on the Unity storage system
description:
- Managing Quota tree on the Unity storage system includes
  Create quota tree,
  Get quota tree,
  Modify quota tree and
  Delete quota tree.
version_added: '1.2.0'
extends_documentation_fragment:
  - dellemc.unity.unity
author:
- Spandita Panigrahi (@panigs7) <ansible.team@dell.com>
options:
  filesystem_name:
    description:
    - The name of the filesystem for which quota tree is created.
    - For creation or modification of a quota tree either I(filesystem_name) or
      I(filesystem_id) is required.
    type: str
  filesystem_id:
    description:
    - The ID of the filesystem for which the quota tree is created.
    - For creation of a quota tree either I(filesystem_id) or
      I(filesystem_name) is required.
    type: str
  nas_server_name:
    description:
    - The name of the NAS server in which the filesystem is created.
    - For creation of a quota tree either I(nas_server_name) or
      I(nas_server_id) is required.
    type: str
  nas_server_id:
    description:
    - The ID of the NAS server in which the filesystem is created.
    - For creation of a quota tree either I(filesystem_id) or
      I(filesystem_name) is required.
    type: str
  tree_quota_id:
    description:
    - The ID of the quota tree.
    - Either I(tree_quota_id) or I(path) to quota tree is required to
      view/modify/delete quota tree.
    type: str
  path:
    description:
    - The path to the quota tree.
    - Either I(tree_quota_id) or I(path) to quota tree is required to
      create/view/modify/delete a quota tree.
    - Path must start with a forward slash '/'.
    type: str
  hard_limit:
    description:
    - Hard limitation for a quota tree on the total space available. If exceeded,
      users in quota tree cannot write data.
    - Value C(0) implies no limit.
    - One of the values of I(soft_limit) and I(hard_limit) can be C(0), however, both cannot be both C(0)
      during creation of a quota tree.
    type: int
  soft_limit:
    description:
    - Soft limitation for a quota tree on the total space available. If exceeded,
      notification will be sent to users in the quota tree for the grace period mentioned, beyond
      which users cannot use space.
    - Value C(0) implies no limit.
    - Both I(soft_limit) and I(hard_limit) cannot be C(0) during creation of quota tree.
    type: int
  cap_unit:
    description:
    - Unit of I(soft_limit) and I(hard_limit) size.
    - It defaults to C(GB) if not specified.
    choices: ['MB', 'GB', 'TB']
    type: str
  description:
    description:
    - Description of a quota tree.
    type: str
  state:
    description:
    - The state option is used to mention the existence of the filesystem
      quota tree.
    type: str
    required: true
    choices: ['absent', 'present']

notes:
  - The I(check_mode) is not supported.
'''

EXAMPLES = r'''
- name: Get quota tree details by quota tree id
  tree_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    tree_quota_id: "treequota_171798700679_10"
    state: "present"

- name: Get quota tree details by quota tree path
  tree_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_name: "fs_2171"
    nas_server_id: "nas_21"
    path: "/test"
    state: "present"

- name: Create quota tree for a filesystem with filesystem id
  tree_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "fs_2171"
    hard_limit: 6
    cap_unit: "TB"
    soft_limit: 5
    path: "/test_new"
    state: "present"

- name: Create quota tree for a filesystem with filesystem name
  tree_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_name: "Test_filesystem"
    nas_server_name: "lglad068"
    hard_limit: 6
    cap_unit: "TB"
    soft_limit: 5
    path: "/test_new"
    state: "present"

- name: Modify quota tree limit usage by quota tree path
  tree_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    path: "/test_new"
    hard_limit: 10
    cap_unit: "TB"
    soft_limit: 8
    state: "present"

- name: Modify quota tree by quota tree id
  tree_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "fs_2171"
    tree_quota_id: "treequota_171798700679_10"
    hard_limit: 12
    cap_unit: "TB"
    soft_limit: 10
    state: "present"

- name: Delete quota tree by quota tree id
  tree_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "fs_2171"
    tree_quota_id: "treequota_171798700679_10"
    state: "absent"

- name: Delete quota tree by path
  tree_quota:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    filesystem_id: "fs_2171"
    path: "/test_new"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true

get_tree_quota_details:
    description: Details of the quota tree.
    returned: When quota tree exists
    type: dict
    contains:
        filesystem:
            description: Filesystem details for which the quota
                         tree is created.
            type: dict
            contains:
                UnityFileSystem:
                    description: Filesystem details for which the
                                 quota tree is created.
                    type: dict
                    contains:
                        id:
                            description: ID of the filesystem for
                                         which the quota tree is create.
                            type: str
        description:
            description: Description of the quota tree.
            type: str
        path:
            description: Path to quota tree.
                         A valid path must start with a forward slash '/'.
                         It is mandatory while creating a quota tree.
            type: str
        hard_limit:
            description: Hard limit of quota tree.
                         If the quota tree's space usage exceeds
                         the hard limit, users in quota tree cannot write data.
            type: int
        soft_limit:
            description: Soft limit of the quota tree.
                         If the quota tree's space usage exceeds the soft limit,
                         the storage system starts to count down based
                         on the specified grace period.
            type: int
        id:
            description: Quota tree ID.
            type: str
        size_used:
            description: Size of used space in the filesystem by the user files.
            type: int
        gp_left:
            description: The grace period left after the
                         soft limit for the user quota is exceeded.
            type: int
        state:
            description: State of the quota tree.
            type: int
    sample: {
        "description": "",
        "existed": true,
        "filesystem": {
            "UnityFileSystem": {
                "hash": 8788549469862,
                "id": "fs_137",
                "name": "test",
                "nas_server": {
                    "id": "nas_1",
                    "name": "lglad072"
                }
            }
        },
        "gp_left": null,
        "hard_limit": "6.0 TB",
        "hash": 8788549497558,
        "id": "treequota_171798694897_1",
        "path": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
        "size_used": 0,
        "soft_limit": "5.0 TB",
        "state": 0
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('tree_quota')

application_type = "Ansible/1.7.1"


class QuotaTree(object):
    """Class with Quota Tree operations"""

    def __init__(self):
        """Define all parameters required by this module"""
        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_quota_tree_parameters())

        mutually_exclusive = [['filesystem_name', 'filesystem_id'],
                              ['nas_server_name', 'nas_server_id']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=False,
            mutually_exclusive=mutually_exclusive)
        utils.ensure_required_libs(self.module)

        self.unity_conn = utils.get_unity_unisphere_connection(
            self.module.params, application_type)

    def check_quota_tree_is_present(self, fs_id, path, tree_quota_id):
        """
            Check if quota tree is present in filesystem.
            :param fs_id: ID of filesystem where quota tree is searched.
            :param path: Path to the quota tree
            :param tree_quota_id: ID of the quota tree
            :return: ID of quota tree if it exists else None.
        """
        if tree_quota_id is None and path is None:
            return None

        all_tree_quota = self.unity_conn.get_tree_quota(filesystem=fs_id,
                                                        id=tree_quota_id,
                                                        path=path)

        if tree_quota_id and len(all_tree_quota) == 0 \
                and self.module.params['state'] == "present":
            errormsg = "Tree quota %s does not exist." % tree_quota_id
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

        if len(all_tree_quota) > 0:
            msg = "Quota tree with id %s is present in filesystem %s" % (all_tree_quota[0].id,
                                                                         fs_id)
            LOG.info(msg)
            return all_tree_quota[0].id
        else:
            return None

    def create_quota_tree(self, fs_id, soft_limit, hard_limit, unit, path, description):
        """
            Create quota tree of a filesystem.
            :param fs_id: ID of filesystem where quota tree is to be created.
            :param soft_limit: Soft limit
            :param hard_limit: Hard limit
            :param unit: Unit of soft limit and hard limit
            :param path: Path to quota tree
            :param description: Description for quota tree
            :return: Dict containing new quota tree details.
        """

        if soft_limit is None and hard_limit is None:
            errormsg = "Both soft limit and hard limit cannot be empty. " \
                       "Please provide atleast one to create quota tree."
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

        soft_limit_in_bytes = utils.get_size_bytes(soft_limit, unit)
        hard_limit_in_bytes = utils.get_size_bytes(hard_limit, unit)
        try:
            obj_tree_quota = self.unity_conn.create_tree_quota(filesystem_id=fs_id, hard_limit=hard_limit_in_bytes,
                                                               soft_limit=soft_limit_in_bytes, path=path,
                                                               description=description)
            LOG.info("Successfully created quota tree")

            if obj_tree_quota:
                return obj_tree_quota
            else:
                return None

        except Exception as e:
            errormsg = "Create quota tree operation at path {0} failed in filesystem {1}" \
                       " with error {2}".format(path, fs_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_filesystem_tree_quota_display_attributes(self, tree_quota_id):
        """Display quota tree attributes
            :param tree_quota_id: Quota tree ID
            :return: Quota tree dict to display
        """
        try:
            tree_quota_obj = self.unity_conn.get_tree_quota(_id=tree_quota_id)
            tree_quota_details = tree_quota_obj._get_properties()
            if tree_quota_obj and tree_quota_obj.existed:
                tree_quota_details['soft_limit'] = utils. \
                    convert_size_with_unit(int(tree_quota_details['soft_limit']))
                tree_quota_details['hard_limit'] = utils. \
                    convert_size_with_unit(int(tree_quota_details['hard_limit']))

                tree_quota_details['filesystem']['UnityFileSystem']['name'] = \
                    tree_quota_obj.filesystem.name
                tree_quota_details['filesystem']['UnityFileSystem'].update(
                    {'nas_server': {'name': tree_quota_obj.filesystem.nas_server.name,
                                    'id': tree_quota_obj.filesystem.nas_server.id}})
                return tree_quota_details

        except Exception as e:
            errormsg = "Failed to display quota tree details {0} with " \
                       "error {1}".format(tree_quota_obj.id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def get_filesystem(self, nas_server=None, name=None, id=None):
        """
            Get filesystem details.
            :param nas_server: Nas server object.
            :param name: Name of filesystem.
            :param id: ID of filesystem.
            :return: Dict containing filesystem details if it exists.
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
            :return: Dict containing nas server details if it exists.
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

    def modify_tree_quota(self, tree_quota_id, soft_limit, hard_limit, unit, description):
        """
            Modify quota tree of filesystem.
            :param tree_quota_id: ID of the quota tree
            :param soft_limit: Soft limit
            :param hard_limit: Hard limit
            :param unit: Unit of soft limit and hard limit
            :param description: Description of quota tree
            :return: Boolean value whether modify quota tree operation is successful.
        """
        try:
            if soft_limit is None and hard_limit is None:
                return False
            tree_quota_obj = self.unity_conn.get_tree_quota(tree_quota_id)._get_properties()
            if soft_limit is None:
                soft_limit_in_bytes = tree_quota_obj['soft_limit']
            else:
                soft_limit_in_bytes = utils.get_size_bytes(soft_limit, unit)
            if hard_limit is None:
                hard_limit_in_bytes = tree_quota_obj['hard_limit']
            else:
                hard_limit_in_bytes = utils.get_size_bytes(hard_limit, unit)

            if description is None:
                description = tree_quota_obj['description']

            if tree_quota_obj:
                if tree_quota_obj['soft_limit'] == soft_limit_in_bytes and \
                        tree_quota_obj['hard_limit'] == hard_limit_in_bytes and \
                        tree_quota_obj['description'] == description:
                    return False
                else:
                    modify_tree_quota = self.unity_conn.modify_tree_quota(tree_quota_id=tree_quota_id,
                                                                          hard_limit=hard_limit_in_bytes,
                                                                          soft_limit=soft_limit_in_bytes,
                                                                          description=description)
                    LOG.info("Successfully modified quota tree")
                    if modify_tree_quota:
                        return True
        except Exception as e:
            errormsg = "Modify quota tree operation {0} failed" \
                       " with error {1}".format(tree_quota_id, str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def delete_tree_quota(self, tree_quota_id):
        """
        Delete quota tree of a filesystem.
        :param tree_quota_id: ID of quota tree
        :return: Boolean whether quota tree is deleted
        """

        try:
            delete_tree_quota_obj = self.unity_conn.delete_tree_quota(tree_quota_id=tree_quota_id)

            if delete_tree_quota_obj:
                return True

        except Exception as e:
            errormsg = "Delete operation of quota tree id:{0} " \
                       "failed with error {1}".format(tree_quota_id,
                                                      str(e))
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def perform_module_operation(self):
        """
        Perform different actions on quota tree module based on parameters
        passed in the playbook
        """
        filesystem_id = self.module.params['filesystem_id']
        filesystem_name = self.module.params['filesystem_name']
        nas_server_name = self.module.params['nas_server_name']
        nas_server_id = self.module.params['nas_server_id']
        cap_unit = self.module.params['cap_unit']
        state = self.module.params['state']
        hard_limit = self.module.params['hard_limit']
        soft_limit = self.module.params['soft_limit']
        path = self.module.params['path']
        description = self.module.params['description']
        tree_quota_id = self.module.params['tree_quota_id']
        create_tree_quota_obj = None
        nas_server_resource = None
        fs_id = None

        '''
        result is a dictionary to contain end state and quota tree details
        '''
        result = dict(
            changed=False,
            create_tree_quota=False,
            modify_tree_quota=False,
            get_tree_quota_details={},
            delete_tree_quota=False

        )

        if (soft_limit or hard_limit) and cap_unit is None:
            cap_unit = 'GB'

        if soft_limit and utils.is_size_negative(soft_limit):
            error_message = "Invalid soft_limit provided, " \
                            "must be greater than or equal to 0"
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

        if hard_limit and utils.is_size_negative(hard_limit):
            error_message = "Invalid hard_limit provided, " \
                            "must be greater than or equal to 0"
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
                fs_id = filesystem_obj[0].id
            else:
                self.module.fail_json(msg="Filesystem does not exist.")

        '''
        Validate path to quota tree
        '''
        if path is not None:
            if utils.is_input_empty(path):
                self.module.fail_json(msg=" Please provide a valid path.")
            elif not path.startswith('/'):
                self.module.fail_json(msg="The path is relative to the root of the file system "
                                          "and must start with a forward slash '/'.")

            if filesystem_id is None and filesystem_name is None:
                self.module.fail_json(msg="Please provide either filesystem_name or fileystem_id.")

        quota_tree_id_present = self.check_quota_tree_is_present(fs_id, path, tree_quota_id)
        tree_quota_id = quota_tree_id_present

        '''
        Create quota tree
        '''

        if (filesystem_id or filesystem_name) and path is not None and state == "present":
            if not tree_quota_id:
                LOG.info("Creating quota tree")
                create_tree_quota_obj = self.create_quota_tree(fs_id, soft_limit, hard_limit,
                                                               cap_unit, path, description)

        if create_tree_quota_obj:
            tree_quota_id = create_tree_quota_obj.id
            result['create_tree_quota'] = True

        '''
        Modify quota tree
        '''

        if tree_quota_id and state == "present":
            LOG.info("Modifying quota tree")
            result['modify_tree_quota'] = self.modify_tree_quota(tree_quota_id, soft_limit, hard_limit, cap_unit,
                                                                 description)

        '''
        Delete quota tree
        '''

        if tree_quota_id is not None and state == "absent":
            LOG.info("Deleting quota tree")
            result['delete_tree_quota'] = self.delete_tree_quota(tree_quota_id)

        '''
        Get quota tree details
        '''
        if state == "present" and tree_quota_id is not None:
            result['get_tree_quota_details'] = self.get_filesystem_tree_quota_display_attributes(tree_quota_id)
        else:
            result['get_tree_quota_details'] = {}

        if result['create_tree_quota'] or result['modify_tree_quota'] or result['delete_tree_quota']:
            result['changed'] = True

        self.module.exit_json(**result)


def get_quota_tree_parameters():
    """This method provide parameters required for the ansible
       quota tree module on Unity"""
    return dict(
        filesystem_id=dict(required=False, type='str'),
        filesystem_name=dict(required=False, type='str'),
        state=dict(required=True, type='str', choices=['present', 'absent']),
        hard_limit=dict(required=False, type='int'),
        soft_limit=dict(required=False, type='int'),
        cap_unit=dict(required=False, type='str', choices=['MB', 'GB', 'TB']),
        tree_quota_id=dict(required=False, type='str'),
        nas_server_name=dict(required=False, type='str'),
        nas_server_id=dict(required=False, type='str'),
        path=dict(required=False, type='str', no_log=True),
        description=dict(required=False, type='str')
    )


def main():
    """ Create Unity quota tree object and perform action on it
        based on user input from playbook"""
    obj = QuotaTree()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
