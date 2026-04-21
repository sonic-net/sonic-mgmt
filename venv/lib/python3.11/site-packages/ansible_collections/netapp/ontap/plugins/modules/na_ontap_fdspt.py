#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: na_ontap_fdspt
short_description: NetApp ONTAP create, delete or modify File Directory security policy tasks
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
version_added: 21.8.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
- Create, modify or remove file directory security policy tasks.

options:
  state:
    description:
    - Whether the specified Policy Task should exist or not.
    choices: ['present', 'absent']
    default: present
    type: str

  name:
    description:
    - Specifies the name of the policy the task will be associated with.
    required: true
    type: str

  vserver:
    description:
    - Specifies the vserver for the File Directory security policy.
    required: true
    type: str

  access_control:
    description:
    - Specifies access control of the task.
    choices: ['file_directory', 'slag']
    type: str

  ntfs_mode:
    description:
    - Specifies NTFS propagation mode.
    choices: ['propagate', 'ignore', 'replace']
    type: str

  ntfs_sd:
    description:
    - Specifies the NTFS security descriptor name.
    type: list
    elements: str

  path:
    description:
    - Specifies the file or folder path of the task. In case of SLAG this path specify the volume or qtree mounted path.
    required: true
    type: str

  security_type:
    description:
    - Specifies the type of security. If not specified ONTAP will default to ntfs.
    choices: ['ntfs', 'nfsv4']
    type: str

  index_num:
    description:
    -  Specifies the index number of a task. Tasks are applied in order. A task with a larger index value is applied after a task with a lower \
       index number. If you do not specify this optional parameter, new tasks are applied to the end of the index list.
    type: int

notes:
- check_mode is supported for this module.
"""

EXAMPLES = """
- name: Create File Directory Security Policy Task
  netapp.ontap.na_ontap_na_ontap_fdspt:
    state: present
    name: "ansible_pl"
    access_control: "file_directory"
    ntfs_sd: "ansible1_sd"
    ntfs_mode: "replace"
    security_type: "ntfs"
    path: "/volume1"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Modify File Directory Security Policy Task
  netapp.ontap.na_ontap_na_ontap_fdspt:
    state: present
    name: "ansible_pl"
    access_control: "file_directory"
    path: "/volume1"
    ntfs_sd: "ansible1_sd"
    ntfs_mode: "replace"
    security_type: "ntfs"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Remove File Directory Security Policy Task
  netapp.ontap.na_ontap_na_ontap_fdspt:
    state: absent
    vserver: "SVM1"
    name: "ansible_pl"
    access_control: "file_directory"
    path: "/volume1"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
"""

RETURN = """

"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh


class NetAppOntapFDSPT():
    """
        Creates, Modifies and removes a File Directory Security Policy Tasks
    """
    def __init__(self):
        """
            Initialize the Ontap File Directory Security Policy Tasks class
        """

        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            path=dict(required=True, type='str'),
            access_control=dict(required=False, choices=['file_directory', 'slag'], type='str'),
            ntfs_sd=dict(required=False, type='list', elements='str'),
            ntfs_mode=dict(required=False, choices=['propagate', 'ignore', 'replace'], type='str'),
            security_type=dict(required=False, choices=['ntfs', 'nfsv4'], type='str'),
            index_num=dict(required=False, type='int')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            self.module.fail_json(msg=self.rest_api.requires_ontap_version('na_ontap_fdspt', '9.6'))

    def get_fdspt(self):
        """
        Get File Directory Security Policy Task
        """
        api = "private/cli/vserver/security/file-directory/policy/task"
        query = {
            'policy-name': self.parameters['name'],
            'path': self.parameters['path'],
            'fields': 'vserver,ntfs-mode,ntfs-sd,security-type,access-control,index-num'
        }

        message, error = self.rest_api.get(api, query)
        records, error = rrh.check_for_0_or_1_records(api, message, error)

        if error:
            self.module.fail_json(msg=error)
        if records:
            if 'ntfs_sd' not in records:  # ntfs_sd is not included in the response if there is not an associated value. Required for modify
                records['ntfs_sd'] = []

        return records if records else None

    def add_fdspt(self):
        """
        Adds a new File Directory Security Policy Task
        """
        api = "private/cli/vserver/security/file-directory/policy/task/add"
        body = {
            'policy-name': self.parameters['name'],
            'vserver': self.parameters['vserver'],
            'path': self.parameters['path']
        }

        for i in ('ntfs_mode', 'ntfs_sd', 'security_type', 'access_control', 'index_num'):
            if i in self.parameters:
                body[i.replace('_', '-')] = self.parameters[i]

        dummy, error = self.rest_api.post(api, body)
        if error:
            self.module.fail_json(msg=error)

    def remove_fdspt(self):
        """
        Deletes a File Directory Security Policy Task
        """
        api = "private/cli/vserver/security/file-directory/policy/task/remove"
        body = {
            'policy-name': self.parameters['name'],
            'vserver': self.parameters['vserver'],
            'path': self.parameters['path']
        }

        dummy, error = self.rest_api.delete(api, body)
        if error:
            self.module.fail_json(msg=error)

    def modify_fdspt(self):
        """
        Modifies a File Directory Security Policy Task
        """
        # Modify endpoint is not functional.
        self.remove_fdspt()
        self.add_fdspt()

    def apply(self):
        current, modify = self.get_fdspt(), None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.add_fdspt()
            elif cd_action == 'delete':
                self.remove_fdspt()
            elif modify:
                self.modify_fdspt()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Creates, deletes and modifies File Directory Security Policy Tasks
    """
    obj = NetAppOntapFDSPT()
    obj.apply()


if __name__ == '__main__':
    main()
