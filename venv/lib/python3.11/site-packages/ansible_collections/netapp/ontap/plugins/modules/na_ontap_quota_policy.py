#!/usr/bin/python

# (c) 2019-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_quota_policy
'''

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = """
module: na_ontap_quota_policy
short_description: NetApp Ontap create, assign, rename or delete quota policy
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap_zapi
version_added: '19.11.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create, assign, rename or delete the quota policy.
options:
  state:
    description:
    - Whether the specified quota policy should exist or not.
    choices: ['present', 'absent']
    default: present
    type: str

  vserver:
    description:
    - Specifies the vserver for the quota policy.
    required: true
    type: str

  name:
    description:
    - Specifies the quota policy name to create or rename to.
    required: true
    type: str

  from_name:
    description:
    - Name of the existing quota policy to be renamed to name.
    type: str

  auto_assign:
    description:
      - when true, assign the policy to the vserver, whether it is newly created, renamed, or already exists.
      - when true, the policy identified by name replaces the already assigned policy.
      - when false, the policy is created if it does not already exist but is not assigned.
    type: bool
    default: true
    version_added: 20.12.0
"""

EXAMPLES = """
- name: Create quota policy
  netapp.ontap.na_ontap_quota_policy:
    state: present
    vserver: SVM1
    name: ansible_policy
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Rename quota policy
  netapp.ontap.na_ontap_quota_policy:
    state: present
    vserver: SVM1
    name: new_ansible
    from_name: ansible
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete quota policy
  netapp.ontap.na_ontap_quota_policy:
    state: absent
    vserver: SVM1
    name: ansible_policy
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils import zapis_svm

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapQuotaPolicy(object):
    """
        Create, assign, rename or delete a quota policy
    """

    def __init__(self):
        """
            Initialize the ONTAP quota policy class
        """

        self.argument_spec = netapp_utils.na_ontap_zapi_only_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            from_name=dict(required=False, type='str'),
            auto_assign=dict(required=False, type='bool', default=True),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('state', 'present', ['name', 'vserver'])
            ],
            supports_check_mode=True
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        if HAS_NETAPP_LIB is False:
            self.module.fail_json(msg='The python NetApp-Lib module is required')
        else:
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_quota_policy(self, policy_name=None):

        if policy_name is None:
            policy_name = self.parameters['name']

        return_value = None
        quota_policy_get_iter = netapp_utils.zapi.NaElement('quota-policy-get-iter')
        quota_policy_info = netapp_utils.zapi.NaElement('quota-policy-info')
        quota_policy_info.add_new_child('policy-name', policy_name)
        quota_policy_info.add_new_child('vserver', self.parameters['vserver'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(quota_policy_info)
        quota_policy_get_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(quota_policy_get_iter, True)
            if result.get_child_by_name('attributes-list'):
                quota_policy_attributes = result['attributes-list']['quota-policy-info']
                return_value = {
                    'name': quota_policy_attributes['policy-name']
                }
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching quota policy %s: %s' % (policy_name, to_native(error)),
                                  exception=traceback.format_exc())
        return return_value

    def create_quota_policy(self):
        """
        Creates a new quota policy
        """
        quota_policy_obj = netapp_utils.zapi.NaElement("quota-policy-create")
        quota_policy_obj.add_new_child("policy-name", self.parameters['name'])
        quota_policy_obj.add_new_child("vserver", self.parameters['vserver'])
        try:
            self.server.invoke_successfully(quota_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating quota policy %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_quota_policy(self):
        """
        Deletes a quota policy
        """
        quota_policy_obj = netapp_utils.zapi.NaElement("quota-policy-delete")
        quota_policy_obj.add_new_child("policy-name", self.parameters['name'])
        try:
            self.server.invoke_successfully(quota_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting quota policy %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def rename_quota_policy(self):
        """
        Rename a quota policy
        """
        quota_policy_obj = netapp_utils.zapi.NaElement("quota-policy-rename")
        quota_policy_obj.add_new_child("policy-name", self.parameters['from_name'])
        quota_policy_obj.add_new_child("vserver", self.parameters['vserver'])
        quota_policy_obj.add_new_child("new-policy-name", self.parameters['name'])
        try:
            self.server.invoke_successfully(quota_policy_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error renaming quota policy %s: %s' % (self.parameters['from_name'], to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        current = self.get_quota_policy()
        # rename and create are mutually exclusive
        rename, cd_action = None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action == 'create' and self.parameters.get('from_name'):
            # create policy by renaming it
            rename = self.na_helper.is_rename_action(self.get_quota_policy(self.parameters['from_name']), current)
            if rename is None:
                self.module.fail_json(msg='Error renaming quota policy: %s does not exist.' % self.parameters['from_name'])

        # check if policy should be assigned
        assign_policy = cd_action == 'create' and self.parameters['auto_assign']
        if cd_action is None and current and self.parameters['auto_assign']:
            # find out if the existing policy needs to be changed
            svm = zapis_svm.get_vserver(self.server, self.parameters['vserver'])
            if svm.get('quota_policy') != self.parameters['name']:
                assign_policy = True
                self.na_helper.changed = True
        if cd_action == 'delete':
            # can't delete if already assigned
            svm = zapis_svm.get_vserver(self.server, self.parameters['vserver'])
            if svm.get('quota_policy') == self.parameters['name']:
                self.module.fail_json(msg='Error policy %s cannot be deleted as it is assigned to the vserver %s' %
                                      (self.parameters['name'], self.parameters['vserver']))

        if self.na_helper.changed and not self.module.check_mode:
            if rename:
                self.rename_quota_policy()
            elif cd_action == 'create':
                self.create_quota_policy()
            elif cd_action == 'delete':
                self.delete_quota_policy()
            if assign_policy:
                zapis_svm.modify_vserver(self.server, self.module, self.parameters['vserver'], modify=dict(quota_policy=self.parameters['name']))
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    """
    Creates the NetApp Ontap quota policy object and runs the correct play task
    """
    obj = NetAppOntapQuotaPolicy()
    obj.apply()


if __name__ == '__main__':
    main()
