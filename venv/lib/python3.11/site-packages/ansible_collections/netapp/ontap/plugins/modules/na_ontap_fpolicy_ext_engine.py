#!/usr/bin/python

# (c) 2021-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_fpolicy_ext_engine
short_description: NetApp ONTAP fPolicy external engine configuration.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: '21.4.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
- Create, delete or modify fpolicy external engine.
options:
  state:
    description:
    - Whether the fPolicy external engine is present or not
    choices: ['present', 'absent']
    default: present
    type: str

  vserver:
    description:
    - the name of the vserver to create the external engine on
    required: true
    type: str

  name:
    description:
    - Name of the external engine.
    required: true
    type: str

  certificate_ca:
    description:
    - Certificate authority name. No default value is set for this field.
    type: str

  certificate_common_name:
    description:
    - FQDN or custom common name of certificate. No default value is set for this field.
    type: str

  certificate_serial:
    description:
    - Serial number of certificate. No default value is set for this field.
    type: str

  extern_engine_type:
    description:
    - External engine type. If the engine is asynchronous, no reply is sent from FPolicy servers. Default value set for this field is synchronous.
    choices: ['synchronous', 'asynchronous']
    type: str

  is_resiliency_enabled:
    description:
    - Indicates if the resiliency with this engine is required.
    - If set to true, the notifications will be stored in a path as resiliency_directory_path
    - If it is false, the notifications will not be stored. Default value is false.
    type: bool

  max_connection_retries:
    description:
    - Number of times storage appliance will attempt to establish a broken connection to FPolicy server. Default value set for this field is 5.
    type: int

  max_server_reqs:
    description:
    - Maximum number of outstanding screen requests that will be queued for an FPolicy Server. Default value set for this field is 50.
    type: int

  port:
    description:
    - Port number of the FPolicy server application.
    type: int

  primary_servers:
    description:
    - Primary FPolicy servers.
    type: list
    elements: str

  recv_buffer_size:
    description:
    - Receive buffer size of connected socket for FPolicy Server. Default value set for this field is 256 kilobytes (256Kb).
    type: int

  resiliency_directory_path:
    description:
    - Directory path under Vserver for storing file access notifications. File access notifications will be stored in a generated file during the outage time.
    - The path is the full, user visible path relative to the Vserver root, and it might be crossing junction mount points.
    type: str

  secondary_servers:
    description:
    - Secondary FPolicy servers. No default value is set for this field.
    type: list
    elements: str

  send_buffer_size:
    description:
    - Send buffer size of connected socket for FPolicy Server. Default value set for this field is 256 kilobytes (256Kb).
    type: int

  ssl_option:
    description:
    - SSL option for external communication. No default value is set for this field
    choices: ['no_auth', 'server_auth', 'mutual_auth']
    type: str

'''

EXAMPLES = """
- name: Create fPolicy external engine
  netapp.ontap.na_ontap_fpolicy_ext_engine:
    state: present
    vserver: svm1
    name: fpolicy_ext_engine
    port: 8787
    extern_engine_type: asynchronous
    primary_servers: ['10.11.12.13', '10.11.12.14']
    ssl_option: no_auth
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Modify fPolicy external engine
  netapp.ontap.na_ontap_fpolicy_ext_engine:
    state: present
    vserver: svm1
    name: fpolicy_ext_engine
    port: 7878
    extern_engine_type: synchronous
    primary_servers: ['10.11.12.15', '10.11.12.16']
    ssl_option: server_auth
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"

- name: Delete fPolicy external engine
  netapp.ontap.na_ontap_fpolicy_ext_engine:
    state: absent
    vserver: svm1
    name: fpolicy_engine
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
import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh


class NetAppOntapFpolicyExtEngine():

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            certificate_ca=dict(required=False, type='str'),
            certificate_common_name=dict(required=False, type='str'),
            certificate_serial=dict(required=False, type='str'),
            extern_engine_type=dict(required=False, type='str', choices=['synchronous', 'asynchronous']),
            is_resiliency_enabled=dict(required=False, type='bool'),
            max_connection_retries=dict(required=False, type='int'),
            max_server_reqs=dict(required=False, type='int'),
            port=dict(required=False, type='int'),
            primary_servers=dict(required=False, type='list', elements='str'),
            recv_buffer_size=dict(required=False, type='int'),
            resiliency_directory_path=dict(required=False, type='str'),
            secondary_servers=dict(required=False, type='list', elements='str'),
            send_buffer_size=dict(required=False, type='int'),
            ssl_option=dict(required=False, type='str', choices=['no_auth', 'server_auth', 'mutual_auth']),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[('state', 'present', ['ssl_option', 'primary_servers', 'port'])],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def create_rest_body(self):
        """
        Create an fPolicy body for a create operation
        :return: body as dict
        """

        body = {
            'vserver': self.parameters['vserver'],
            'engine-name': self.parameters['name'],
            'primary_servers': self.parameters['primary_servers'],
            'port': self.parameters['port'],
            'ssl_option': self.parameters['ssl_option']
        }

        list_of_options = ['secondary_servers', 'is_resiliency_enabled', 'resiliency_directory_path',
                           'max_connection_retries', 'max_server_reqs', 'recv_buffer_size', 'send_buffer_size',
                           'certificate_ca', 'certificate_common_name', 'certificate_serial', 'extern_engine_type']

        for option in list_of_options:
            if option in self.parameters:
                body[option] = self.parameters[option]

        return body

    def create_zapi_api(self, api):
        """
        Create an the ZAPI API request for fpolicy modify and create
        :return: ZAPI API object
        """
        fpolicy_ext_engine_obj = netapp_utils.zapi.NaElement(api)
        fpolicy_ext_engine_obj.add_new_child('engine-name', self.parameters['name'])
        fpolicy_ext_engine_obj.add_new_child('port-number', self.na_helper.get_value_for_int(from_zapi=False, value=self.parameters['port']))
        fpolicy_ext_engine_obj.add_new_child('ssl-option', self.parameters['ssl_option'])

        primary_servers_obj = netapp_utils.zapi.NaElement('primary-servers')

        for primary_server in self.parameters['primary_servers']:
            primary_servers_obj.add_new_child('ip-address', primary_server)
        fpolicy_ext_engine_obj.add_child_elem(primary_servers_obj)

        if 'secondary_servers' in self.parameters:
            secondary_servers_obj = netapp_utils.zapi.NaElement('secondary-servers')

            for secondary_server in self.parameters['secondary_servers']:
                primary_servers_obj.add_new_child('ip-address', secondary_server)
            fpolicy_ext_engine_obj.add_child_elem(secondary_servers_obj)

        if 'is_resiliency_enabled' in self.parameters:
            fpolicy_ext_engine_obj.add_new_child(
                'is-resiliency-enabled',
                self.na_helper.get_value_for_bool(from_zapi=False, value=self.parameters['is_resiliency_enabled'])
            )
        if 'resiliency_directory_path' in self.parameters:
            fpolicy_ext_engine_obj.add_new_child('resiliency-directory-path', self.parameters['resiliency_directory_path'])
        if 'max_connection_retries' in self.parameters:
            fpolicy_ext_engine_obj.add_new_child(
                'max-connection-retries',
                self.na_helper.get_value_for_int(from_zapi=False, value=self.parameters['max_connection_retries'])
            )
        if 'max_server_reqs' in self.parameters:
            fpolicy_ext_engine_obj.add_new_child(
                'max-server-requests',
                self.na_helper.get_value_for_int(from_zapi=False, value=self.parameters['max_server_reqs'])
            )
        if 'recv_buffer_size' in self.parameters:
            fpolicy_ext_engine_obj.add_new_child(
                'recv-buffer-size',
                self.na_helper.get_value_for_int(from_zapi=False, value=self.parameters['recv_buffer_size'])
            )
        if 'send_buffer_size' in self.parameters:
            fpolicy_ext_engine_obj.add_new_child(
                'send-buffer-size',
                self.na_helper.get_value_for_int(from_zapi=False, value=self.parameters['send_buffer_size'])
            )
        if 'certificate_ca' in self.parameters:
            fpolicy_ext_engine_obj.add_new_child('certificate-ca', self.parameters['certificate_ca'])
        if 'certificate_common_name' in self.parameters:
            fpolicy_ext_engine_obj.add_new_child('certificate-common-name', self.parameters['certificate_common_name'])
        if 'certificate_serial' in self.parameters:
            fpolicy_ext_engine_obj.add_new_child('certificate-serial', self.parameters['certificate_serial'])
        if 'extern_engine_type' in self.parameters:
            fpolicy_ext_engine_obj.add_new_child('extern-engine-type', self.parameters['extern_engine_type'])

        return fpolicy_ext_engine_obj

    def create_fpolicy_ext_engine(self):
        """
        Create an fPolicy external engine
        :return: nothing
        """

        if self.use_rest:
            api = "/private/cli/vserver/fpolicy/policy/external-engine"
            body = self.create_rest_body()

            dummy, error = self.rest_api.post(api, body)
            if error:
                self.module.fail_json(msg=error)
        else:
            fpolicy_ext_engine_obj = self.create_zapi_api('fpolicy-policy-external-engine-create')

            try:
                self.server.invoke_successfully(fpolicy_ext_engine_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error creating fPolicy external engine %s on vserver %s: %s' %
                    (self.parameters['name'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

    def modify_fpolicy_ext_engine(self, modify):
        """
        Modify an fPolicy external engine
        :return: nothing
        """

        if self.use_rest:
            api = "/private/cli/vserver/fpolicy/policy/external-engine"
            query = {
                'vserver': self.parameters['vserver'],
                'engine-name': self.parameters['name']
            }

            dummy, error = self.rest_api.patch(api, modify, query)
            if error:
                self.module.fail_json(msg=error)
        else:
            fpolicy_ext_engine_obj = self.create_zapi_api('fpolicy-policy-external-engine-modify')

            try:
                self.server.invoke_successfully(fpolicy_ext_engine_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error modifying fPolicy external engine %s on vserver %s: %s' %
                    (self.parameters['name'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

    def delete_fpolicy_ext_engine(self):
        """
        Delete an fPolicy external engine
        :return: nothing
        """

        if self.use_rest:
            api = "/private/cli/vserver/fpolicy/policy/external-engine"
            query = {
                'vserver': self.parameters['vserver'],
                'engine-name': self.parameters['name']
            }

            dummy, error = self.rest_api.delete(api, query)

            if error:
                self.module.fail_json(msg=error)
        else:

            fpolicy_ext_engine_obj = netapp_utils.zapi.NaElement('fpolicy-policy-external-engine-delete')
            fpolicy_ext_engine_obj.add_new_child('engine-name', self.parameters['name'])

            try:
                self.server.invoke_successfully(fpolicy_ext_engine_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error deleting fPolicy external engine %s on vserver %s: %s' %
                    (self.parameters['name'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

    def get_fpolicy_ext_engine(self):
        """
        Check to see if the fPolicy external engine exists or not
        :return: dict of engine properties if exist, None if not
        """
        return_value = None

        if self.use_rest:
            fields = [
                "vserver",
                "engine-name",
                "primary-servers",
                "port",
                "secondary-servers",
                "extern-engine-type",
                "ssl-option",
                "max-connection-retries",
                "max-server-reqs",
                "certificate-common-name",
                "certificate-serial",
                "certificate-ca",
                "recv-buffer-size",
                "send-buffer-size",
                "is-resiliency-enabled",
                "resiliency-directory-path"
            ]

            api = "private/cli/vserver/fpolicy/policy/external-engine"
            query = {
                'fields': ','.join(fields),
                'engine-name': self.parameters['name'],
                'vserver': self.parameters['vserver']
            }
            message, error = self.rest_api.get(api, query)

            return_info, error = rrh.check_for_0_or_1_records(api, message, error)
            if return_info is None:
                return None

            return_value = message['records'][0]
            return return_value
        else:

            fpolicy_ext_engine_obj = netapp_utils.zapi.NaElement('fpolicy-policy-external-engine-get-iter')
            fpolicy_ext_engine_config = netapp_utils.zapi.NaElement('fpolicy-external-engine-info')
            fpolicy_ext_engine_config.add_new_child('engine-name', self.parameters['name'])
            fpolicy_ext_engine_config.add_new_child('vserver', self.parameters['vserver'])
            query = netapp_utils.zapi.NaElement('query')
            query.add_child_elem(fpolicy_ext_engine_config)
            fpolicy_ext_engine_obj.add_child_elem(query)

            try:
                result = self.server.invoke_successfully(fpolicy_ext_engine_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(
                    msg='Error searching for fPolicy engine %s on vserver %s: %s' %
                    (self.parameters['name'], self.parameters['vserver'], to_native(error)), exception=traceback.format_exc()
                )

            if result.get_child_by_name('attributes-list'):
                fpolicy_ext_engine_attributes = result['attributes-list']['fpolicy-external-engine-info']

                primary_servers = []
                primary_servers_elem = fpolicy_ext_engine_attributes.get_child_by_name('primary-servers')
                for primary_server in primary_servers_elem.get_children():
                    primary_servers.append(primary_server.get_content())

                secondary_servers = []
                if fpolicy_ext_engine_attributes.get_child_by_name('secondary-servers'):
                    secondary_servers_elem = fpolicy_ext_engine_attributes.get_child_by_name('secondary-servers')

                    for secondary_server in secondary_servers_elem.get_children():
                        secondary_servers.append(secondary_server.get_content())

                return_value = {
                    'vserver': fpolicy_ext_engine_attributes.get_child_content('vserver'),
                    'name': fpolicy_ext_engine_attributes.get_child_content('engine-name'),
                    'certificate_ca': fpolicy_ext_engine_attributes.get_child_content('certificate-ca'),
                    'certificate_common_name': fpolicy_ext_engine_attributes.get_child_content('certificate-common-name'),
                    'certificate_serial': fpolicy_ext_engine_attributes.get_child_content('certificate-serial'),
                    'extern_engine_type': fpolicy_ext_engine_attributes.get_child_content('extern-engine-type'),
                    'is_resiliency_enabled': self.na_helper.get_value_for_bool(
                        from_zapi=True,
                        value=fpolicy_ext_engine_attributes.get_child_content('is-resiliency-enabled')
                    ),
                    'max_connection_retries': self.na_helper.get_value_for_int(
                        from_zapi=True,
                        value=fpolicy_ext_engine_attributes.get_child_content('max-connection-retries')
                    ),
                    'max_server_reqs': self.na_helper.get_value_for_int(
                        from_zapi=True,
                        value=fpolicy_ext_engine_attributes.get_child_content('max-server-requests')
                    ),
                    'port': self.na_helper.get_value_for_int(
                        from_zapi=True,
                        value=fpolicy_ext_engine_attributes.get_child_content('port-number')
                    ),
                    'primary_servers': primary_servers,
                    'secondary_servers': secondary_servers,
                    'recv_buffer_size': self.na_helper.get_value_for_int(
                        from_zapi=True,
                        value=fpolicy_ext_engine_attributes.get_child_content('recv-buffer-size')
                    ),
                    'resiliency_directory_path': fpolicy_ext_engine_attributes.get_child_content('resiliency-directory-path'),
                    'send_buffer_size': self.na_helper.get_value_for_int(
                        from_zapi=True,
                        value=fpolicy_ext_engine_attributes.get_child_content('send-buffer-size')
                    ),
                    'ssl_option': fpolicy_ext_engine_attributes.get_child_content('ssl-option'),
                }

        return return_value

    def apply(self):
        current, modify = self.get_fpolicy_ext_engine(), None

        cd_action = self.na_helper.get_cd_action(current, self.parameters)

        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)

        if self.na_helper.changed:
            if not self.module.check_mode:
                if cd_action == 'create':
                    self.create_fpolicy_ext_engine()
                elif cd_action == 'delete':
                    self.delete_fpolicy_ext_engine()
                elif modify:
                    self.modify_fpolicy_ext_engine(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Execute action from playbook
    """
    command = NetAppOntapFpolicyExtEngine()
    command.apply()


if __name__ == '__main__':
    main()
