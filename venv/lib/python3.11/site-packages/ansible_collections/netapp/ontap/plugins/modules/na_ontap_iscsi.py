#!/usr/bin/python

# (c) 2017-2022, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_iscsi
'''
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''

module: na_ontap_iscsi
short_description: NetApp ONTAP manage iSCSI service
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - create, delete, start, stop iSCSI service on SVM.

options:

  state:
    description:
      - Whether the service should be present or deleted.
    choices: ['present', 'absent']
    type: str
    default: present

  service_state:
    description:
      - Whether the specified service should running.
    choices: ['started', 'stopped']
    type: str

  vserver:
    required: true
    type: str
    description:
      - The name of the vserver to use.

  target_alias:
    type: str
    description:
      - The iSCSI target alias of the iSCSI service.
      - The target alias can contain one (1) to 128 characters and feature any printable character except space (" ").
      - A PATCH request with an empty alias ("") clears the alias.
      - This option is REST only.
    version_added: 22.2.0

'''

EXAMPLES = """
- name: Create iscsi service
  netapp.ontap.na_ontap_iscsi:
    state: present
    service_state: started
    vserver: ansibleVServer
    target_alias: ansibleSVM
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Stop Iscsi service
  netapp.ontap.na_ontap_iscsi:
    state: present
    service_state: stopped
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete Iscsi service
  netapp.ontap.na_ontap_iscsi:
    state: absent
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """

"""

import traceback
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapISCSI:

    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            service_state=dict(required=False, type='str', choices=['started', 'stopped'], default=None),
            vserver=dict(required=True, type='str'),
            target_alias=dict(required=False, type='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.uuid = None
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        # Set up Rest API
        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()
        self.unsupported_zapi_properties = ['target_alias']
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            for unsupported_zapi_property in self.unsupported_zapi_properties:
                if self.parameters.get(unsupported_zapi_property) is not None:
                    msg = "Error: %s option is not supported with ZAPI.  It can only be used with REST." % unsupported_zapi_property
                    self.module.fail_json(msg=msg)
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])
        self.safe_strip()

    def safe_strip(self):
        """ strip the left and right spaces of string """
        if 'target_alias' in self.parameters:
            self.parameters['target_alias'] = self.parameters['target_alias'].strip()
        return

    def get_iscsi(self):
        """
        Return details about the iscsi service

        :return: Details about the iscsi service
        :rtype: dict
        """
        if self.use_rest:
            return self.get_iscsi_rest()
        iscsi_info = netapp_utils.zapi.NaElement('iscsi-service-get-iter')
        iscsi_attributes = netapp_utils.zapi.NaElement('iscsi-service-info')

        iscsi_attributes.add_new_child('vserver', self.parameters['vserver'])

        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(iscsi_attributes)

        iscsi_info.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(iscsi_info, True)
        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg="Error finding iscsi service in %s: %s" % (self.parameters['vserver'], to_native(e)),
                                  exception=traceback.format_exc())
        return_value = None

        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) >= 1:

            iscsi = result.get_child_by_name(
                'attributes-list').get_child_by_name('iscsi-service-info')
            if iscsi:
                is_started = 'started' if iscsi.get_child_content('is-available') == 'true' else 'stopped'
                return_value = {
                    'service_state': is_started
                }
        return return_value

    def create_iscsi_service(self):
        """
        Create iscsi service and start if requested
        """
        if self.use_rest:
            return self.create_iscsi_service_rest()

        iscsi_service = netapp_utils.zapi.NaElement.create_node_with_children(
            'iscsi-service-create',
            **{'start': 'true' if self.parameters.get('service_state', 'started') == 'started' else 'false'
               })

        try:
            self.server.invoke_successfully(iscsi_service, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg="Error creating iscsi service: % s" % (to_native(e)),
                                  exception=traceback.format_exc())

    def delete_iscsi_service(self, current):
        """
         Delete the iscsi service
        """
        if self.use_rest:
            return self.delete_iscsi_service_rest(current)

        if current['service_state'] == 'started':
            self.stop_iscsi_service()

        iscsi_delete = netapp_utils.zapi.NaElement.create_node_with_children('iscsi-service-destroy')

        try:
            self.server.invoke_successfully(iscsi_delete, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg="Error deleting iscsi service on vserver %s: %s" % (self.parameters['vserver'], to_native(e)),
                                  exception=traceback.format_exc())

    def stop_iscsi_service(self):
        """
         Stop iscsi service
        """

        iscsi_stop = netapp_utils.zapi.NaElement.create_node_with_children('iscsi-service-stop')

        try:
            self.server.invoke_successfully(iscsi_stop, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg="Error Stopping iscsi service on vserver %s: %s" % (self.parameters['vserver'], to_native(e)),
                                  exception=traceback.format_exc())

    def start_iscsi_service(self):
        """
        Start iscsi service
        """
        iscsi_start = netapp_utils.zapi.NaElement.create_node_with_children(
            'iscsi-service-start')

        try:
            self.server.invoke_successfully(iscsi_start, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg="Error starting iscsi service on vserver %s: %s" % (self.parameters['vserver'], to_native(e)),
                                  exception=traceback.format_exc())

    def get_iscsi_rest(self):
        api = 'protocols/san/iscsi/services'
        query = {'svm.name': self.parameters['vserver']}
        fields = 'svm,enabled,target.alias'
        record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg="Error finding iscsi service in %s: %s" % (self.parameters['vserver'], error))
        if record:
            self.uuid = record['svm']['uuid']
            is_started = 'started' if record['enabled'] else 'stopped'
            return {
                'service_state': is_started,
                'target_alias': "" if self.na_helper.safe_get(record, ['target', 'alias']) is None else record['target']['alias'],
            }
        return None

    def create_iscsi_service_rest(self):
        api = 'protocols/san/iscsi/services'
        body = {
            'svm.name': self.parameters['vserver'],
            'enabled': True if self.parameters.get('service_state', 'started') == 'started' else False
        }
        if 'target_alias' in self.parameters:
            body['target.alias'] = self.parameters['target_alias']
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error creating iscsi service: % s" % error)

    def delete_iscsi_service_rest(self, current):
        # stop iscsi service before delete.
        if current['service_state'] == 'started':
            self.start_or_stop_iscsi_service_rest('stopped')
        api = 'protocols/san/iscsi/services'
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.uuid)
        if error:
            self.module.fail_json(msg="Error deleting iscsi service on vserver %s: %s" % (self.parameters["vserver"], error))

    def start_or_stop_iscsi_service_rest(self, service_state):
        api = 'protocols/san/iscsi/services'
        enabled = True if service_state == 'started' else False
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, {'enabled': enabled})
        if error:
            self.module.fail_json(msg="Error %s iscsi service on vserver %s: %s" % (service_state[0:5] + 'ing', self.parameters["vserver"], error))

    def modify_iscsi_service_state_and_target(self, modify):
        body = {}
        api = 'protocols/san/iscsi/services'
        if 'target_alias' in modify:
            body['target.alias'] = self.parameters['target_alias']
            dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body)
            if error:
                self.module.fail_json(msg="Error modifying iscsi service target alias on vserver %s: %s" % (self.parameters["vserver"], error))

    def modify_iscsi_service_rest(self, modify, current):
        if self.use_rest:
            if 'service_state' in modify:
                self.start_or_stop_iscsi_service_rest(modify['service_state'])
            if 'target_alias' in modify:
                self.modify_iscsi_service_state_and_target(modify)
        else:
            if 'service_state' in modify:
                if modify['service_state'] == 'started':
                    self.start_iscsi_service()
                else:
                    self.stop_iscsi_service()

    def apply(self):
        current = self.get_iscsi()
        modify = None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.na_helper.get_modified_attributes(current, self.parameters) if cd_action is None else None

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_iscsi_service()
            elif cd_action == 'delete':
                self.delete_iscsi_service(current)
            elif modify:
                self.modify_iscsi_service_rest(modify, current)
        # TODO: include other details about the lun (size, etc.)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action)
        self.module.exit_json(**result)


def main():
    v = NetAppOntapISCSI()
    v.apply()


if __name__ == '__main__':
    main()
