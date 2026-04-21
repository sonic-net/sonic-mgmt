#!/usr/bin/python
""" this is ndmp module

 (c) 2019-2025, NetApp, Inc
 # GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}


DOCUMENTATION = '''
---
module: na_ontap_ndmp
short_description: NetApp ONTAP NDMP services configuration
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.9.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
    - Modify NDMP Services.

options:

  vserver:
    description:
    - Name of the vserver.
    required: true
    type: str

  abort_on_disk_error:
    description:
    - Enable abort on disk error.
    type: bool

  authtype:
    description:
    - Authentication type.
    type: list
    elements: str

  backup_log_enable:
    description:
    - Enable backup log.
    type: bool

  data_port_range:
    description:
    - Data port range. Modification not supported for data Vservers.
    type: str

  debug_enable:
    description:
    - Enable debug.
    type: bool

  debug_filter:
    description:
    - Debug filter.
    type: str

  dump_detailed_stats:
    description:
    - Enable logging of VM stats for dump.
    type: bool

  dump_logical_find:
    description:
    - Enable logical find for dump.
    type: str

  enable:
    description:
    - Enable NDMP on vserver.
    type: bool

  fh_dir_retry_interval:
    description:
    - FH throttle value for dir.
    type: int

  fh_node_retry_interval:
    description:
    - FH throttle value for node.
    type: int

  ignore_ctime_enabled:
    description:
    - Ignore ctime.
    type: bool

  is_secure_control_connection_enabled:
    description:
    - Is secure control connection enabled.
    type: bool

  offset_map_enable:
    description:
    - Enable offset map.
    type: bool

  per_qtree_exclude_enable:
    description:
    - Enable per qtree exclusion.
    type: bool

  preferred_interface_role:
    description:
    - Preferred interface role.
    type: list
    elements: str

  restore_vm_cache_size:
    description:
    - Restore VM file cache size. Value range [4-1024]
    type: int

  secondary_debug_filter:
    description:
    - Secondary debug filter.
    type: str

  tcpnodelay:
    description:
    - Enable TCP nodelay.
    type: bool

  tcpwinsize:
    description:
    - TCP window size.
    type: int

  ndmp_user:
    description:
    - The name of the NDMP user.
    - This field cannot be specified in a PATCH method.
    type: str
    version_added: 23.0.0
'''

EXAMPLES = '''
- name: Modify ndmp
  netapp.ontap.na_ontap_ndmp:
    vserver: ansible
    abort_on_disk_error: true
    authtype: plaintext,challenge
    backup_log_enable: true
    data_port_range: 8000-9000
    debug_enable: true
    debug_filter: filter
    dump_detailed_stats: true
    dump_logical_find: default
    enable: true
    fh_dir_retry_interval: 100
    fh_node_retry_interval: 100
    ignore_ctime_enabled: true
    is_secure_control_connection_enabled: true
    offset_map_enable: true
    per_qtree_exclude_enable: true
    preferred_interface_role: node_mgmt,intercluster
    restore_vm_cache_size: 1000
    secondary_debug_filter: filter
    tcpnodelay: true
    tcpwinsize: 10000
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true

- name: generate password - REST
  netapp.ontap.na_ontap_ndmp:
    ndmp_user: "ndmp_user"
    vserver: vs0
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
'''

RETURN = '''
'''

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppONTAPNdmp(object):
    '''
    modify vserver cifs security
    '''
    def __init__(self):
        self.use_rest = False

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.modifiable_options = dict(
            abort_on_disk_error=dict(required=False, type='bool'),
            authtype=dict(required=False, type='list', elements='str'),
            backup_log_enable=dict(required=False, type='bool'),
            data_port_range=dict(required=False, type='str'),
            debug_enable=dict(required=False, type='bool'),
            debug_filter=dict(required=False, type='str'),
            dump_detailed_stats=dict(required=False, type='bool'),
            dump_logical_find=dict(required=False, type='str'),
            enable=dict(required=False, type='bool'),
            fh_dir_retry_interval=dict(required=False, type='int'),
            fh_node_retry_interval=dict(required=False, type='int'),
            ignore_ctime_enabled=dict(required=False, type='bool'),
            is_secure_control_connection_enabled=dict(required=False, type='bool'),
            offset_map_enable=dict(required=False, type='bool'),
            per_qtree_exclude_enable=dict(required=False, type='bool'),
            preferred_interface_role=dict(required=False, type='list', elements='str'),
            restore_vm_cache_size=dict(required=False, type='int'),
            secondary_debug_filter=dict(required=False, type='str'),
            tcpnodelay=dict(required=False, type='bool'),
            tcpwinsize=dict(required=False, type='int')
        )
        self.argument_spec.update(dict(
            vserver=dict(required=True, type='str'),
            ndmp_user=dict(required=False, type='str'),
        ))

        self.argument_spec.update(self.modifiable_options)

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # API should be used for ONTAP 9.6 or higher, ZAPI for lower version
        self.rest_api = OntapRestAPI(self.module)
        unsupported_rest_properties = ['abort_on_disk_error', 'backup_log_enable', 'data_port_range',
                                       'debug_enable', 'debug_filter', 'dump_detailed_stats',
                                       'dump_logical_find', 'fh_dir_retry_interval', 'fh_node_retry_interval',
                                       'ignore_ctime_enabled', 'is_secure_control_connection_enabled',
                                       'offset_map_enable', 'per_qtree_exclude_enable', 'preferred_interface_role',
                                       'restore_vm_cache_size', 'secondary_debug_filter', 'tcpnodelay', 'tcpwinsize']
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties)
        if 'ndmp_user' in self.parameters and not self.rest_api.meets_rest_minimum_version(True, 9, 7, 0):
            self.module.fail_json(msg="Error: ndmp_user %s requires ONTAP 9.7 or later version." % self.parameters['ndmp_user'])
        if not self.use_rest:
            if HAS_NETAPP_LIB is False:
                self.module.fail_json(msg="the python NetApp-Lib module is required")
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def get_ndmp_svm_uuid(self):

        """
            Get a svm's UUID
            :return: uuid of the node
            """
        params = {'svm.name': self.parameters['vserver']}
        api = "protocols/ndmp/svms"
        message, error = self.rest_api.get(api, params)
        if error is not None:
            self.module.fail_json(msg=error)
        if 'records' in message and len(message['records']) == 0:
            self.module.fail_json(msg='Error fetching uuid for vserver %s: ' % (self.parameters['vserver']))
        if len(message.keys()) == 0:
            error = "No information collected from %s: %s" % (api, repr(message))
            self.module.fail_json(msg=error)
        elif 'records' not in message:
            error = "Unexpected response from %s: %s" % (api, repr(message))
            self.module.fail_json(msg=error)
        return message['records'][0]['svm']['uuid']

    def ndmp_get_password(self, uuid, ndmp_user):
        api = '/protocols/ndmp/svms/%s/passwords/%s' % (uuid, ndmp_user)
        params = {'fields': 'password'}
        message, error = self.rest_api.get(api, params)
        if error:
            self.module.fail_json(msg=error)
        if message.get("password"):
            return message["password"]
        return None

    def ndmp_get_iter(self, uuid=None):
        """
        get current vserver ndmp attributes.
        :return: a dict of ndmp attributes.
        """
        if self.use_rest:
            data = dict()
            params = {'fields': 'authentication_types,enabled'}
            api = '/protocols/ndmp/svms/' + uuid
            message, error = self.rest_api.get(api, params)
            if message:
                return {
                    'enable': message.get('enabled'),
                    'authtype': message.get('authentication_types')
                }
            if error:
                self.module.fail_json(msg=error)
            return data
        else:
            ndmp_get = netapp_utils.zapi.NaElement('ndmp-vserver-attributes-get-iter')
            query = netapp_utils.zapi.NaElement('query')
            ndmp_info = netapp_utils.zapi.NaElement('ndmp-vserver-attributes-info')
            ndmp_info.add_new_child('vserver', self.parameters['vserver'])
            query.add_child_elem(ndmp_info)
            ndmp_get.add_child_elem(query)
            ndmp_details = dict()
            try:
                result = self.server.invoke_successfully(ndmp_get, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error fetching ndmp from %s: %s'
                                      % (self.parameters['vserver'], to_native(error)),
                                      exception=traceback.format_exc())

            if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0:
                ndmp_attributes = result.get_child_by_name('attributes-list').get_child_by_name('ndmp-vserver-attributes-info')
                self.get_ndmp_details(ndmp_details, ndmp_attributes)
            return ndmp_details

    def get_ndmp_details(self, ndmp_details, ndmp_attributes):
        """
        :param ndmp_details: a dict of current ndmp.
        :param ndmp_attributes: ndmp returned from api call in xml format.
        :return: None
        """
        for option in self.modifiable_options:
            option_type = self.modifiable_options[option]['type']
            if option_type == 'bool':
                ndmp_details[option] = self.str_to_bool(ndmp_attributes.get_child_content(self.attribute_to_name(option)))
            elif option_type == 'int':
                ndmp_details[option] = int(ndmp_attributes.get_child_content(self.attribute_to_name(option)))
            elif option_type == 'list':
                child_list = ndmp_attributes.get_child_by_name(self.attribute_to_name(option))
                values = [child.get_content() for child in child_list.get_children()]
                ndmp_details[option] = values
            else:
                ndmp_details[option] = ndmp_attributes.get_child_content(self.attribute_to_name(option))

    def modify_ndmp(self, modify):
        """
        :param modify: A list of attributes to modify
        :return: None
        """
        if self.use_rest:
            ndmp = dict()
            uuid = self.get_ndmp_svm_uuid()
            if 'enable' in modify:
                ndmp['enabled'] = modify['enable']
            if 'authtype' in modify:
                ndmp['authentication_types'] = modify['authtype']
            api = "protocols/ndmp/svms/" + uuid
            dummy, error = self.rest_api.patch(api, ndmp)
            if error:
                self.module.fail_json(msg=error)
        else:

            ndmp_modify = netapp_utils.zapi.NaElement('ndmp-vserver-attributes-modify')
            for attribute in modify:
                if attribute == 'authtype':
                    authtypes = netapp_utils.zapi.NaElement('authtype')
                    types = self.parameters['authtype']
                    for authtype in types:
                        authtypes.add_new_child('ndmpd-authtypes', authtype)
                    ndmp_modify.add_child_elem(authtypes)
                elif attribute == 'preferred_interface_role':
                    preferred_interface_roles = netapp_utils.zapi.NaElement('preferred-interface-role')
                    roles = self.parameters['preferred_interface_role']
                    for role in roles:
                        preferred_interface_roles.add_new_child('netport-role', role)
                    ndmp_modify.add_child_elem(preferred_interface_roles)
                else:
                    ndmp_modify.add_new_child(self.attribute_to_name(attribute), str(self.parameters[attribute]))
            try:
                self.server.invoke_successfully(ndmp_modify, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as exc:
                self.module.fail_json(msg='Error modifying ndmp on %s: %s'
                                      % (self.parameters['vserver'], to_native(exc)),
                                      exception=traceback.format_exc())

    @staticmethod
    def attribute_to_name(attribute):
        return str.replace(attribute, '_', '-')

    @staticmethod
    def str_to_bool(value):
        return value == 'true'

    def apply(self):
        """Call modify operations."""
        uuid = None
        if self.use_rest:
            # we only have the svm name, we need to the the uuid for the svm
            uuid = self.get_ndmp_svm_uuid()
            if 'ndmp_user' in self.parameters:
                new_password = self.ndmp_get_password(uuid, self.parameters['ndmp_user'])
                self.module.exit_json(changed=False, password=new_password)
        current = self.ndmp_get_iter(uuid=uuid)
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if modify:
                    self.modify_ndmp(modify)
        result = netapp_utils.generate_result(self.na_helper.changed, modify=modify)
        self.module.exit_json(**result)


def main():
    obj = NetAppONTAPNdmp()
    obj.apply()


if __name__ == '__main__':
    main()
