#!/usr/bin/python

# (c) 2019-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Delete/Modify Name Service Switch.
  - Deleting name service switch not supported in REST.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
module: na_ontap_name_service_switch
options:
  state:
    choices: ['present', 'absent']
    description:
      - Whether the specified ns-switch should exist or not.
    default: present
    type: str
  vserver:
    description:
      - Name of the vserver to use.
    required: true
    type: str
  database_type:
    description:
      - Name services switch database.
    choices: ['hosts','group', 'passwd', 'netgroup', 'namemap']
    required: true
    type: str
  sources:
    description:
      - Type of sources.
      - Possible values include files,dns,ldap,nis.
    type: list
    elements: str

short_description: "NetApp ONTAP Manage name service switch"
'''

EXAMPLES = """
- name: Create name service database
  netapp.ontap.na_ontap_name_service_switch:
    state: present
    database_type: namemap
    sources: files,ldap
    vserver: "{{ Vserver name }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Modify name service database sources
  netapp.ontap.na_ontap_name_service_switch:
    state: present
    database_type: namemap
    sources: files
    vserver: "{{ Vserver name }}"
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
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, rest_vserver


class NetAppONTAPNsswitch:
    """
    Class with NVMe service methods
    """

    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            database_type=dict(required=True, type='str', choices=['hosts', 'group', 'passwd', 'netgroup', 'namemap']),
            sources=dict(required=False, type='list', elements='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        if self.parameters.get('sources') is not None:
            self.parameters['sources'] = [source.strip() for source in self.parameters['sources']]
            if '' in self.parameters['sources']:
                self.module.fail_json(msg="Error: Invalid value '' specified for sources")
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.svm_uuid = None
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_name_service_switch(self):
        """
        get current name service switch config
        :return: dict of current name service switch
        """
        if self.use_rest:
            return self.get_name_service_switch_rest()
        nss_iter = netapp_utils.zapi.NaElement('nameservice-nsswitch-get-iter')
        nss_info = netapp_utils.zapi.NaElement('namservice-nsswitch-config-info')
        db_type = netapp_utils.zapi.NaElement('nameservice-database')
        db_type.set_content(self.parameters['database_type'])
        query = netapp_utils.zapi.NaElement('query')
        nss_info.add_child_elem(db_type)
        query.add_child_elem(nss_info)
        nss_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(nss_iter, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching name service switch info for %s: %s' %
                                  (self.parameters['vserver'], to_native(error)), exception=traceback.format_exc())
        return_value = None
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) == 1:
            nss_sources = result.get_child_by_name('attributes-list').get_child_by_name(
                'namservice-nsswitch-config-info').get_child_by_name('nameservice-sources')
            # nameservice-sources will not present in result if the value is '-'
            if nss_sources:
                sources = [sources.get_content() for sources in nss_sources.get_children()]
                return_value = {'sources': sources}
            else:
                return_value = {'sources': []}
        return return_value

    def create_name_service_switch(self):
        """
        create name service switch config
        :return: None
        """
        nss_create = netapp_utils.zapi.NaElement('nameservice-nsswitch-create')
        nss_create.add_new_child('nameservice-database', self.parameters['database_type'])
        nss_sources = netapp_utils.zapi.NaElement('nameservice-sources')
        nss_create.add_child_elem(nss_sources)
        for source in self.parameters['sources']:
            nss_sources.add_new_child('nss-source-type', source)
        try:
            self.server.invoke_successfully(nss_create,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error on creating name service switch config on vserver %s: %s'
                                      % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def delete_name_service_switch(self):
        """
        delete name service switch
        :return: None
        """
        nss_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'nameservice-nsswitch-destroy', **{'nameservice-database': self.parameters['database_type']})
        try:
            self.server.invoke_successfully(nss_delete,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error on deleting name service switch config on vserver %s: %s'
                                      % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def modify_name_service_switch(self, modify):
        """
        modify name service switch
        :param modify: dict of modify attributes
        :return: None
        """
        if self.use_rest:
            return self.modify_name_service_switch_rest()
        nss_modify = netapp_utils.zapi.NaElement('nameservice-nsswitch-modify')
        nss_modify.add_new_child('nameservice-database', self.parameters['database_type'])
        nss_sources = netapp_utils.zapi.NaElement('nameservice-sources')
        nss_modify.add_child_elem(nss_sources)
        if 'sources' in modify:
            for source in self.parameters['sources']:
                nss_sources.add_new_child('nss-source-type', source)
        try:
            self.server.invoke_successfully(nss_modify, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error on modifying name service switch config on vserver %s: %s'
                                  % (self.parameters['vserver'], to_native(error)),
                                  exception=traceback.format_exc())

    def get_name_service_switch_rest(self):
        record, error = rest_vserver.get_vserver(self.rest_api, self.parameters['vserver'], 'nsswitch,uuid')
        if error:
            self.module.fail_json(msg='Error fetching name service switch info for %s: %s' %
                                  (self.parameters['vserver'], to_native(error)))
        if not record:
            self.module.fail_json(msg="Error: Specified vserver %s not found" % self.parameters['vserver'])
        self.svm_uuid = record['uuid']
        # if database type is already deleted by ZAPI call, REST will not have the database key.
        # setting it to [] help to set the value in REST patch call.
        database_type = self.na_helper.safe_get(record, ['nsswitch', self.parameters['database_type']])
        return {'sources': database_type if database_type else []}

    def modify_name_service_switch_rest(self):
        api = 'svm/svms'
        body = {
            'nsswitch': {
                self.parameters['database_type']: self.parameters['sources']
            }
        }
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.svm_uuid, body)
        if error:
            self.module.fail_json(msg='Error on modifying name service switch config on vserver %s: %s'
                                  % (self.parameters['vserver'], to_native(error)))

    def apply(self):
        current = self.get_name_service_switch()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action == 'delete' and self.use_rest:
            self.module.fail_json(msg="Error: deleting name service switch not supported in REST.")
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_name_service_switch()
            elif cd_action == 'delete':
                self.delete_name_service_switch()
            elif modify:
                self.modify_name_service_switch(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    '''Applyoperations from playbook'''
    nss = NetAppONTAPNsswitch()
    nss.apply()


if __name__ == '__main__':
    main()
