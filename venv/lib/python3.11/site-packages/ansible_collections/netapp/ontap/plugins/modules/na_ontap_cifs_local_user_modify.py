#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = '''
module: na_ontap_cifs_local_user_modify
short_description: NetApp ONTAP modify local CIFS user.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '21.4.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
- Modify a local CIFS user
options:
  name:
    description:
    - The name of the local cifs user
    required: true
    type: str

  vserver:
    description:
    - the name of the data vserver to use.
    required: true
    type: str

  is_account_disabled:
    description:
    - Whether the local cifs user is disabled or not
    type: bool

  description:
    description:
    - the description for the local cifs user
    type: str

  full_name:
    description:
    - the full name for the local cifs user
    type: str
    '''

EXAMPLES = """
- name: Enable local CIFS Administrator account
  na_ontap_cifs_local_user_modify:
    name: BUILTIN\\administrators
    vserver: ansible
    is_account_disabled: false
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Disable local CIFS Administrator account
  na_ontap_cifs_local_user_modify:
    name: BUILTIN\\administrators
    vserver: ansible
    is_account_disabled: true
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
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


class NetAppOntapCifsLocalUserModify():
    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            name=dict(required=True, type='str'),
            vserver=dict(required=True, type='str'),
            is_account_disabled=dict(required=False, type='bool'),
            full_name=dict(required=False, type='str'),
            description=dict(required=False, type='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        self.module.warn('This module is deprecated and na_ontap_cifs_local_user should be used instead')
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_cifs_local_user(self):
        """
        Return a CIFS local user
        :return: None if there is no CIFS local user matching
        """
        return_value = None
        if self.use_rest:
            api = "private/cli/vserver/cifs/users-and-groups/local-user"
            query = {
                'fields': 'user-name,full-name,is-account-disabled,description',
                'user-name': self.parameters['name'],
                'vserver': self.parameters['vserver']
            }
            record, error = rest_generic.get_one_record(self.rest_api, api, query=query)
            if error:
                self.module.fail_json(msg=error)
            if record:
                return_value = {
                    'name': record['user_name'],
                    'is_account_disabled': record['is_account_disabled'],
                    'vserver': record['vserver'],
                    'description': record.get('description', ''),
                    'full_name': record.get('full_name', '')
                }
        else:
            cifs_local_user_obj = netapp_utils.zapi.NaElement('cifs-local-user-get-iter')
            cifs_local_user_info = netapp_utils.zapi.NaElement('cifs-local-user')
            cifs_local_user_info.add_new_child('user-name', self.parameters['name'])
            query = netapp_utils.zapi.NaElement('query')
            query.add_child_elem(cifs_local_user_info)
            cifs_local_user_obj.add_child_elem(query)
            try:
                result = self.server.invoke_successfully(cifs_local_user_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error getting user %s on vserver %s: %s' %
                                          (self.parameters['name'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc())

            if result.get_child_by_name('attributes-list'):
                local_cifs_user_attributes = result['attributes-list']['cifs-local-user']

                return_value = {
                    'name': local_cifs_user_attributes['user-name'],
                    'is_account_disabled': self.na_helper.get_value_for_bool(from_zapi=True, value=local_cifs_user_attributes['is-account-disabled']),
                    'vserver': local_cifs_user_attributes['vserver'],
                    'full_name': '',
                    'description': '',
                }

                if local_cifs_user_attributes['full-name']:
                    return_value['full_name'] = local_cifs_user_attributes['full-name']

                if local_cifs_user_attributes['description']:
                    return_value['description'] = local_cifs_user_attributes['description']

        return return_value

    def modify_cifs_local_user(self, modify):
        """
        Modifies a local cifs user
        :return: None
        """
        if self.use_rest:
            api = "private/cli/vserver/cifs/users-and-groups/local-user"
            query = {
                "user-name": self.parameters['name'],
                'vserver': self.parameters['vserver']
            }

            dummy, error = self.rest_api.patch(api, modify, query)
            if error:
                self.module.fail_json(msg=error, modify=modify)
        else:
            cifs_local_user_obj = netapp_utils.zapi.NaElement("cifs-local-user-modify")
            cifs_local_user_obj.add_new_child('user-name', self.parameters['name'])
            cifs_local_user_obj.add_new_child('is-account-disabled',
                                              self.na_helper.get_value_for_bool(from_zapi=False, value=self.parameters['is_account_disabled']))

            if 'full_name' in self.parameters:
                cifs_local_user_obj.add_new_child('full-name', self.parameters['full_name'])

            if 'description' in self.parameters:
                cifs_local_user_obj.add_new_child('description', self.parameters['description'])

            try:
                self.server.invoke_successfully(cifs_local_user_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg="Error modifying local CIFS user %s on vserver %s: %s" %
                                      (self.parameters['name'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc())

    def apply(self):
        current = self.get_cifs_local_user()
        if not current:
            error = "User %s does not exist on vserver %s" % (self.parameters['name'], self.parameters['vserver'])
            self.module.fail_json(msg=error)

        if self.use_rest:
            # name is a key, and REST does not allow to change it
            # it should match anyway, but REST may prepend the domain name
            self.parameters['name'] = current['name']
        modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed and not self.module.check_mode:
            self.modify_cifs_local_user(modify)

        result = netapp_utils.generate_result(self.na_helper.changed, modify=modify)
        self.module.exit_json(**result)


def main():
    """
    Execute action from playbook
    """
    command = NetAppOntapCifsLocalUserModify()
    command.apply()


if __name__ == '__main__':
    main()
