#!/usr/bin/python

# (c) 2020-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'certified'
}

DOCUMENTATION = """

module: na_ontap_file_directory_policy
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
short_description: NetApp ONTAP create, delete, or modify vserver security file-directory policy
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_zapi
version_added: 20.8.0
description:
  - Create, modify, or destroy vserver security file-directory policy
  - Add or remove task from policy.
  - Each time a policy/task is created/modified, automatically apply policy to vserver.
options:
  state:
    description:
      - Whether the specified policy or task should exist or not.
    choices: ['present', 'absent']
    default: present
    type: str

  vserver:
    description:
      - Specifies the vserver for the policy.
    required: true
    type: str

  policy_name:
    description:
      - Specifies the name of the policy.
    type: str
    required: true

  access_control:
    description:
      - Specifies the access control of task to be applied.
    choices: ['file_directory', 'slag']
    type: str

  ntfs_mode:
    description:
      - Specifies NTFS Propagation Mode.
    choices: ['propagate', 'ignore', 'replace']
    type: str

  ntfs_sd:
    description:
      - Specifies NTFS security descriptor identifier.
    type: list
    elements: str

  path:
    description:
      - Specifies the file or folder path of the task.
      - If path is specified and the policy which the task is adding to, does not exist, it will create the policy first then add the task to it.
      - If path is specified, delete operation only removes task from policy.
    type: str

  security_type:
    description:
      - Specifies the type of security.
    type: str
    choices: ['ntfs', 'nfsv4']

  ignore_broken_symlinks:
    description:
      - Skip Broken Symlinks.
      - Options used when applying the policy to vserver.
    type: bool

"""

EXAMPLES = """
- name: Create policy
  netapp.ontap.na_ontap_file_directory_policy:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    state: present
    vserver: ansible
    policy_name: file_policy
    ignore_broken_symlinks: false

- name: Add task to existing file_policy
  netapp.ontap.na_ontap_file_directory_policy:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    state: present
    vserver: ansible
    policy_name: file_policy
    path: /vol
    ntfs_sd: ansible_sd
    ntfs_mode: propagate

- name: Delete task from file_policy.
  netapp.ontap.na_ontap_file_directory_policy:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    state: absent
    vserver: ansible
    policy_name: file_policy
    path: /vol

- name: Delete file_policy along with the tasks.
  netapp.ontap.na_ontap_file_directory_policy:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    state: absent
    vserver: ansible
    policy_name: file_policy
"""

RETURN = """
"""

import traceback
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapFilePolicy(object):

    def __init__(self):
        """
            Initialize the Ontap file directory policy class
        """

        self.argument_spec = netapp_utils.na_ontap_zapi_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            policy_name=dict(required=True, type='str'),
            access_control=dict(required=False, type='str', choices=['file_directory', 'slag']),
            ntfs_mode=dict(required=False, choices=['propagate', 'ignore', 'replace']),
            ntfs_sd=dict(required=False, type='list', elements='str'),
            path=dict(required=False, type='str'),
            security_type=dict(required=False, type='str', choices=['ntfs', 'nfsv4']),
            ignore_broken_symlinks=dict(required=False, type='bool')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        if HAS_NETAPP_LIB is False:
            self.module.fail_json(msg='The python NetApp-Lib module is required')
        else:
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def create_policy(self):
        policy_obj = netapp_utils.zapi.NaElement("file-directory-security-policy-create")
        policy_obj.add_new_child('policy-name', self.parameters['policy_name'])
        try:
            self.server.invoke_successfully(policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(
                msg='Error creating file-directory policy %s: %s' % (self.parameters['policy_name'], to_native(error)),
                exception=traceback.format_exc())

    def get_policy_iter(self):
        policy_get_iter = netapp_utils.zapi.NaElement('file-directory-security-policy-get-iter')
        policy_info = netapp_utils.zapi.NaElement('file-directory-security-policy')
        policy_info.add_new_child('vserver', self.parameters['vserver'])
        policy_info.add_new_child('policy-name', self.parameters['policy_name'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(policy_info)
        policy_get_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(policy_get_iter, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching file-directory policy %s: %s'
                                      % (self.parameters['policy_name'], to_native(error)),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            attributes_list = result.get_child_by_name('attributes-list')
            policy = attributes_list.get_child_by_name('file-directory-security-policy')
            return policy.get_child_content('policy-name')
        return None

    def remove_policy(self):
        remove_policy = netapp_utils.zapi.NaElement('file-directory-security-policy-delete')
        remove_policy.add_new_child('policy-name', self.parameters['policy_name'])
        try:
            self.server.invoke_successfully(remove_policy, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(
                msg='Error removing file-directory policy %s: %s' % (self.parameters['policy_name'], to_native(error)),
                exception=traceback.format_exc())

    def get_task_iter(self):
        task_get_iter = netapp_utils.zapi.NaElement('file-directory-security-policy-task-get-iter')
        task_info = netapp_utils.zapi.NaElement('file-directory-security-policy-task')
        task_info.add_new_child('vserver', self.parameters['vserver'])
        task_info.add_new_child('policy-name', self.parameters['policy_name'])
        task_info.add_new_child('path', self.parameters['path'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(task_info)
        task_get_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(task_get_iter, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching task from file-directory policy %s: %s'
                                      % (self.parameters['policy_name'], to_native(error)),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            attributes_list = result.get_child_by_name('attributes-list')
            task = attributes_list.get_child_by_name('file-directory-security-policy-task')
            task_result = dict()
            task_result['path'] = task.get_child_content('path')
            if task.get_child_by_name('ntfs-mode'):
                task_result['ntfs_mode'] = task.get_child_content('ntfs-mode')
            if task.get_child_by_name('security-type'):
                task_result['security_type'] = task.get_child_content('security-type')
            if task.get_child_by_name('ntfs-sd'):
                task_result['ntfs_sd'] = [ntfs_sd.get_content() for ntfs_sd in task.get_child_by_name('ntfs-sd').get_children()]
            return task_result
        return None

    def add_task_to_policy(self):
        policy_add_task = netapp_utils.zapi.NaElement('file-directory-security-policy-task-add')
        policy_add_task.add_new_child('path', self.parameters['path'])
        policy_add_task.add_new_child('policy-name', self.parameters['policy_name'])
        if self.parameters.get('access_control') is not None:
            policy_add_task.add_new_child('access-control', self.parameters['access_control'])
        if self.parameters.get('ntfs_mode') is not None:
            policy_add_task.add_new_child('ntfs-mode', self.parameters['ntfs_mode'])
        if self.parameters.get('ntfs_sd') is not None:
            ntfs_sds = netapp_utils.zapi.NaElement('ntfs-sd')
            for ntfs_sd in self.parameters['ntfs_sd']:
                ntfs_sds.add_new_child('file-security-ntfs-sd', ntfs_sd)
            policy_add_task.add_child_elem(ntfs_sds)
        if self.parameters.get('security_type') is not None:
            policy_add_task.add_new_child('security-type', self.parameters['security_type'])
        try:
            self.server.invoke_successfully(policy_add_task, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error adding task to file-directory policy %s: %s'
                                      % (self.parameters['policy_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def remove_task_from_policy(self):
        policy_remove_task = netapp_utils.zapi.NaElement('file-directory-security-policy-task-remove')
        policy_remove_task.add_new_child('path', self.parameters['path'])
        policy_remove_task.add_new_child('policy-name', self.parameters['policy_name'])
        try:
            self.server.invoke_successfully(policy_remove_task, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error removing task from file-directory policy %s: %s'
                                      % (self.parameters['policy_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_task(self, modify):
        policy_modify_task = netapp_utils.zapi.NaElement('file-directory-security-policy-task-modify')
        policy_modify_task.add_new_child('path', self.parameters['path'])
        policy_modify_task.add_new_child('policy-name', self.parameters['policy_name'])
        if modify.get('ntfs_mode') is not None:
            policy_modify_task.add_new_child('ntfs-mode', self.parameters['ntfs_mode'])
        if modify.get('ntfs_sd') is not None:
            ntfs_sds = netapp_utils.zapi.NaElement('ntfs-sd')
            for ntfs_sd in self.parameters['ntfs_sd']:
                ntfs_sds.add_new_child('file-security-ntfs-sd', ntfs_sd)
            policy_modify_task.add_child_elem(ntfs_sds)
        if modify.get('security_type') is not None:
            policy_modify_task.add_new_child('security-type', self.parameters['security_type'])
        try:
            self.server.invoke_successfully(policy_modify_task, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying task in file-directory policy %s: %s'
                                      % (self.parameters['policy_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def set_sd(self):
        set_sd = netapp_utils.zapi.NaElement('file-directory-security-set')
        set_sd.add_new_child('policy-name', self.parameters['policy_name'])
        if self.parameters.get('ignore-broken-symlinks'):
            set_sd.add_new_child('ignore-broken-symlinks', str(self.parameters['ignore_broken_symlinks']))
        try:
            self.server.invoke_successfully(set_sd, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error applying file-directory policy %s: %s'
                                      % (self.parameters['policy_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        current = self.get_policy_iter()
        cd_action, task_cd_action, task_modify = None, None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if self.parameters.get('path'):
            current_task = self.get_task_iter()
            task_cd_action = self.na_helper.get_cd_action(current_task, self.parameters)
            if task_cd_action is None and self.parameters['state'] == 'present':
                task_modify = self.na_helper.get_modified_attributes(current_task, self.parameters)
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if self.parameters.get('path'):
                    if task_cd_action == 'create':
                        # if policy doesn't exist, create the policy first.
                        if cd_action == 'create':
                            self.create_policy()
                        self.add_task_to_policy()
                        self.set_sd()
                    elif task_cd_action == 'delete':
                        # delete the task, not the policy.
                        self.remove_task_from_policy()
                    elif task_modify:
                        self.modify_task(task_modify)
                        self.set_sd()
                else:
                    if cd_action == 'create':
                        self.create_policy()
                        self.set_sd()
                    elif cd_action == 'delete':
                        self.remove_policy()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, extra_responses={'task action': task_cd_action,
                                                                                                  'task modify': task_modify})
        self.module.exit_json(**result)


def main():
    """
    Creates, deletes and modifies file directory policy
    """
    obj = NetAppOntapFilePolicy()
    obj.apply()


if __name__ == '__main__':
    main()
