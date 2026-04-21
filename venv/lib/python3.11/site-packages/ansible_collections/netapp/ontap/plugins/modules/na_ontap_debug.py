#!/usr/bin/python
"""
create Debug module to diagnose netapp-lib import and connection
"""

# (c) 2020-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''
module: na_ontap_debug
short_description: NetApp ONTAP Debug netapp-lib import and connection.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 21.1.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Display issues related to importing netapp-lib and connection with diagnose
options:
  vserver:
    description:
    - The vserver name to test for ZAPI tunneling.
    required: false
    type: str
'''
EXAMPLES = """
- name: Check import netapp-lib
  netapp.ontap.na_ontap_debug:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""
import sys
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.rest_user import get_users
from ansible_collections.netapp.ontap.plugins.module_utils.rest_vserver import get_vserver


class NetAppONTAPDebug(object):
    """Class with Debug methods"""

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            vserver=dict(required=False, type="str"),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        self.log_list = []
        self.error_list = []
        self.note_list = []
        self.server = None

    def list_versions(self):
        self.log_list.append('Ansible version: %s' % netapp_utils.ANSIBLE_VERSION)
        self.log_list.append('ONTAP collection version: %s' % netapp_utils.COLLECTION_VERSION)
        self.log_list.append('Python version: %s' % sys.version[:3])
        self.log_list.append('Python executable path: %s' % sys.executable)

    def import_lib(self):
        if not netapp_utils.has_netapp_lib():
            msgs = [
                'Error importing netapp-lib or a dependency: %s.' % str(netapp_utils.IMPORT_EXCEPTION),
                'Install the python netapp-lib module or a missing dependency.',
                'Additional diagnostic information:',
                'Python Executable Path: %s.' % sys.executable,
                'Python Version: %s.' % sys.version,
                'System Path: %s.' % ','.join(sys.path),
            ]
            self.error_list.append('  '.join(msgs))
            return
        self.log_list.append('netapp-lib imported successfully.')

    def check_connection(self, connection_type):
        """
        check connection errors and diagnose
        """
        error_string = None
        result = None
        if connection_type == "REST":
            api = 'cluster'
            message, error_string = self.rest_api.get(api)
        elif connection_type == "ZAPI":
            if 'vserver' not in self.parameters:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])
            version_obj = netapp_utils.zapi.NaElement("system-get-version")
            try:
                result = self.server.invoke_successfully(version_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                error_string = to_native(error)
        else:
            self.module.fail_json(msg='Internal error, unexpected connection type: %s' % connection_type)

        if error_string is not None:
            summary_msg = None
            error_patterns = ['Connection timed out',
                              'Resource temporarily unavailable',
                              'ConnectTimeoutError',
                              'Network is unreachable']
            if any(x in error_string for x in error_patterns):
                summary_msg = 'Error: invalid or unreachable hostname: %s' % self.parameters['hostname']
                if 'vserver' in self.parameters:
                    summary_msg += ' for SVM: %s ' % self.parameters['vserver']
                self.error_list.append('Error in hostname - Address does not exist or is not reachable: ' + error_string)
                self.error_list.append(summary_msg + ' using %s.' % connection_type)
                return
            error_patterns = ['Name or service not known', 'Name does not resolve']
            if any(x in error_string for x in error_patterns):
                summary_msg = 'Error: unknown or not resolvable hostname: %s' % self.parameters['hostname']
                if 'vserver' in self.parameters:
                    summary_msg += ' for SVM: %s ' % self.parameters['vserver']
                self.error_list.append('Error in hostname - DNS name cannot be resolved: ' + error_string)
                self.error_list.append('%s cannot be resolved using %s.' % (summary_msg, connection_type))
            else:
                self.error_list.append('Other error for hostname: %s using %s: %s.' % (self.parameters['hostname'], connection_type, error_string))
                self.error_list.append('Unclassified, see msg')
            return False

        ontap_version = message['version']['full'] if connection_type == 'REST' else result['version']
        self.log_list.append('%s connected successfully.' % connection_type)
        self.log_list.append('ONTAP version: %s' % ontap_version)
        return True

    def list_interfaces(self, vserver_name):
        vserver, error = get_vserver(self.rest_api, vserver_name, fields='ip_interfaces')
        if not error and not vserver:
            error = 'not found'
        if error:
            self.error_list.append('Error getting vserver in list_interfaces: %s: %s' % (vserver_name, error))
        else:
            interfaces = vserver.get('ip_interfaces')
            if not interfaces:
                self.error_list.append('Error vserver is not associated with a network interface: %s' % vserver_name)
                return
            for interface in interfaces:
                data = [vserver_name]
                for field in (['name'], ['ip', 'address'], ['services']):
                    value = self.na_helper.safe_get(interface, field)
                    if isinstance(value, list):
                        value = ','.join(value)
                    if field == ['services'] and value and 'management' not in value:
                        self.note_list.append('NOTE: no management policy in services for %s: %s' % (data, value))
                    data.append(value)
                self.log_list.append('vserver: %s, interface: %s, IP: %s, service policies: %s' % tuple(data))

    def validate_user(self, user):
        locked = user.get('locked')
        if locked:
            self.note_list.append('NOTE: user: %s is locked on vserver: %s' % (user['name'], self.na_helper.safe_get(user, ['owner', 'name'])))
        applications = user.get('applications', [])
        apps = [app['application'] for app in applications]
        role = self.na_helper.safe_get(user, ['role', 'name'])
        for application in ('http', 'ontapi', 'console'):
            if application not in apps and (application != 'console' or role == 'admin'):
                self.note_list.append('NOTE: application %s not found for user: %s: %s' % (application, user['name'], apps))
                if application == 'console':
                    self.note_list.append("NOTE: console access is only needed for na_ontap_command.")
        has_http = locked is False and 'http' in apps
        has_ontapi = locked is False and 'ontapi' in apps
        return has_http, has_ontapi

    def list_users(self, vserver_name=None, user_name=None):
        query = {'owner.name': vserver_name} if vserver_name else {'name': user_name}
        users, error = get_users(self.rest_api, query, 'applications,locked,owner,role')
        if not error and not users:
            error = 'none found'
        name = vserver_name or user_name
        if error:
            if 'not authorized for that command' in error:
                self.log_list.append('Not autorized to get accounts for: %s: %s' % (name, error))
            else:
                self.error_list.append('Error getting accounts for: %s: %s' % (name, error))
        else:
            one_http, one_ontapi = False, False
            for user in users:
                data = {}
                for field in ('owner', 'name', 'role', 'locked', 'applications'):
                    if field in ('owner', 'role'):
                        value = str(self.na_helper.safe_get(user, [field, 'name']))
                    else:
                        value = str(user.get(field))
                    data[field] = value
                self.log_list.append(', '. join('%s: %s' % x for x in data.items()))
                has_http, has_ontapi = self.validate_user(user)
                one_http |= has_http
                one_ontapi |= has_ontapi
            msg = 'Error: no unlocked user for %s on vserver: %s'if vserver_name else\
                  'Error: %s is not enabled for user %s'
            if not one_http:
                self.error_list.append(msg % ('http', name))
            if not one_ontapi:
                self.error_list.append(msg % ('ontapi', name))

    def check_vserver(self, name):

        self.list_interfaces(name)
        self.list_users(vserver_name=name)

    def apply(self):
        """
        Apply debug
        """
        # report Ansible and our collection versions
        self.list_versions()

        # check import netapp-lib
        self.import_lib()

        # check zapi connection errors only if import successful
        if netapp_utils.has_netapp_lib():
            self.check_connection("ZAPI")

        # check rest connection errors
        has_rest = self.check_connection("REST")

        if has_rest:
            self.list_users(user_name=self.parameters.get('username'))
            if 'vserver' in self.parameters:
                self.check_vserver(self.parameters['vserver'])

        msgs = {}
        if self.note_list:
            msgs['notes'] = self.note_list
        if self.error_list:
            msgs['msg'] = self.error_list
            if self.log_list:
                msgs['msg_passed'] = self.log_list
            self.module.fail_json(**msgs)
        msgs['msg'] = self.log_list
        self.module.exit_json(**msgs)


def main():
    """Execute action"""
    debug_obj = NetAppONTAPDebug()
    debug_obj.apply()


if __name__ == '__main__':
    main()
