#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Delete NVMe Service
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
module: na_ontap_nvme
options:
  state:
    choices: ['present', 'absent']
    description:
      - Whether the specified NVMe should exist or not.
    default: present
    type: str
  vserver:
    description:
      - Name of the vserver to use.
    required: true
    type: str
  status_admin:
    description:
      - Whether the status of NVMe should be up or down
    type: bool
short_description: "NetApp ONTAP Manage NVMe Service"
version_added: 2.8.0
'''

EXAMPLES = """
- name: Create NVMe
  netapp.ontap.na_ontap_nvme:
    state: present
    status_admin: false
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify NVMe
  netapp.ontap.na_ontap_nvme:
    state: present
    status_admin: true
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete NVMe
  netapp.ontap.na_ontap_nvme:
    state: absent
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppONTAPNVMe:
    """
    Class with NVMe service methods
    """

    def __init__(self):
        self.svm_uuid = None
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            status_admin=dict(required=False, type='bool')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_nvme(self):
        """
        Get current nvme details
        :return: dict if nvme exists, None otherwise
        """
        if self.use_rest:
            return self.get_nvme_rest()
        nvme_get = netapp_utils.zapi.NaElement('nvme-get-iter')
        query = {
            'query': {
                'nvme-target-service-info': {
                    'vserver': self.parameters['vserver']
                }
            }
        }
        nvme_get.translate_struct(query)
        try:
            result = self.server.invoke_successfully(nvme_get, enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching nvme info: %s' % to_native(error),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            attributes_list = result.get_child_by_name('attributes-list')
            nvme_info = attributes_list.get_child_by_name('nvme-target-service-info')
            return {'status_admin': self.na_helper.get_value_for_bool(True, nvme_info.get_child_content('is-available'))}
        return None

    def create_nvme(self):
        """
        Create NVMe service
        """
        if self.use_rest:
            return self.create_nvme_rest()
        nvme_create = netapp_utils.zapi.NaElement('nvme-create')
        if self.parameters.get('status_admin') is not None:
            options = {'is-available': self.na_helper.get_value_for_bool(False, self.parameters['status_admin'])}
            nvme_create.translate_struct(options)
        try:
            self.server.invoke_successfully(nvme_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating nvme for vserver %s: %s'
                                  % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_nvme(self):
        """
        Delete NVMe service
        """
        if self.use_rest:
            return self.delete_nvme_rest()
        nvme_delete = netapp_utils.zapi.NaElement('nvme-delete')
        try:
            self.server.invoke_successfully(nvme_delete, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting nvme for vserver %s: %s'
                                  % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_nvme(self, status=None):
        """
        Modify NVMe service
        """
        if status is None:
            status = self.parameters['status_admin']
        if self.use_rest:
            return self.modify_nvme_rest(status)
        options = {'is-available': status}
        nvme_modify = netapp_utils.zapi.NaElement('nvme-modify')
        nvme_modify.translate_struct(options)
        try:
            self.server.invoke_successfully(nvme_modify, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying nvme for vserver %s: %s'
                                  % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def get_nvme_rest(self):
        api = 'protocols/nvme/services'
        params = {'svm.name': self.parameters['vserver'], 'fields': 'enabled'}
        record, error = rest_generic.get_one_record(self.rest_api, api, params)
        if error:
            self.module.fail_json(msg='Error fetching nvme info for vserver: %s' % self.parameters['vserver'])
        if record:
            self.svm_uuid = record['svm']['uuid']
            record['status_admin'] = record.pop('enabled')
            return record
        return None

    def create_nvme_rest(self):
        api = 'protocols/nvme/services'
        body = {'svm.name': self.parameters['vserver']}
        if self.parameters.get('status_admin') is not None:
            body['enabled'] = self.parameters['status_admin']
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error creating nvme for vserver %s: %s' % (self.parameters['vserver'],
                                                                                  to_native(error)),
                                  exception=traceback.format_exc())

    def delete_nvme_rest(self):
        api = 'protocols/nvme/services'
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.svm_uuid)
        if error:
            self.module.fail_json(msg='Error deleting nvme for vserver %s: %s' % (self.parameters['vserver'],
                                                                                  to_native(error)),
                                  exception=traceback.format_exc())

    def modify_nvme_rest(self, status):
        if status == 'false':
            status = False
        api = 'protocols/nvme/services'
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.svm_uuid, {'enabled': status})
        if error:
            self.module.fail_json(msg='Error modifying nvme for vserver: %s' % self.parameters['vserver'])

    def apply(self):
        """
        Apply action to NVMe service
        """
        modify = None
        current = self.get_nvme()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if self.parameters.get('status_admin') is not None:
            if cd_action is None and self.parameters['state'] == 'present':
                modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_nvme()
            elif cd_action == 'delete':
                # NVMe status_admin needs to be down before deleting it
                self.modify_nvme('false')
                self.delete_nvme()
            elif modify:
                self.modify_nvme()
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """Execute action"""
    community_obj = NetAppONTAPNVMe()
    community_obj.apply()


if __name__ == '__main__':
    main()
