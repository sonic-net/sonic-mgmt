#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_user
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''

module: na_ontap_user

short_description: NetApp ONTAP user configuration and management
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
- Create or destroy users.

options:
  state:
    description:
      - Whether the specified user should exist or not.
    choices: ['present', 'absent']
    type: str
    default: 'present'
  name:
    description:
      - The name of the user to manage.
    required: true
    type: str
  application_strs:
    version_added: 21.6.0
    description:
      - List of applications to grant access to.
      - This option maintains backward compatibility with the existing C(applications) option, but is limited.
      - It is recommended to use the new C(application_dicts) option which provides more flexibility.
      - Creating a login with application console, telnet, rsh, and service-processor for a data vserver is not supported.
      - Module supports both service-processor and service_processor choices.
      - ZAPI requires service-processor, while REST requires service_processor, except for an issue with ONTAP 9.6 and 9.7.
      - snmp is not supported in REST.
      - Either C(application_dicts) or C(application_strs) is required.
    type: list
    elements: str
    choices: ['console', 'http','ontapi','rsh','snmp','service_processor','service-processor','sp','ssh','telnet']
    aliases:
      - application
      - applications
  application_dicts:
    version_added: 21.6.0
    description:
      - List of applications to grant access to.  Provides better control on applications and authentication methods.
      - Creating a login with application console, telnet, rsh, and service-processor for a data vserver is not supported.
      - Module supports both service-processor and service_processor choices.
      - ZAPI requires service-processor, while REST requires service_processor, except for an issue with ONTAP 9.6 and 9.7.
      - snmp is not supported in REST.
      - Either C(application_dicts) or C(application_strs) is required.
    type: list
    elements: dict
    suboptions:
      application:
        description: name of the application.
        type: str
        choices: ['console', 'http','ontapi','rsh','snmp','service_processor','service-processor','sp','ssh','telnet']
        required: true
      authentication_methods:
        description: list of authentication methods for the application (see C(authentication_method)).
        type: list
        elements: str
        choices: ['community', 'password', 'publickey', 'domain', 'nsswitch', 'usm', 'cert', 'saml']
        required: true
      second_authentication_method:
        description: when using ssh, optional additional authentication method for MFA.
        type: str
        choices: ['none', 'password', 'publickey', 'nsswitch', 'totp']
  authentication_method:
    description:
      - Authentication method for the application.  If you need more than one method, use C(application_dicts).
      - Not all authentication methods are valid for an application.
      - Valid authentication methods for each application are as denoted in I(authentication_choices_description).
      - Password for console application
      - Password, domain, nsswitch, cert, saml for http application.
      - Password, domain, nsswitch, cert, saml for ontapi application.
      - SAML is only supported with REST, but seems to work with ZAPI as well.
      - Community for snmp application (when creating SNMPv1 and SNMPv2 users).
      - The usm and community for snmp application (when creating SNMPv3 users).
      - Password for sp application.
      - Password for rsh application.
      - Password for telnet application.
      - Password, publickey, domain, nsswitch for ssh application.
      - Required when C(application_strs) is present.
    type: str
    choices: ['community', 'password', 'publickey', 'domain', 'nsswitch', 'usm', 'cert', 'saml']
  set_password:
    description:
      - Password for the user account.
      - It is ignored for creating snmp users, but is required for creating non-snmp users.
      - For an existing user, this value will be used as the new password.
    type: str
  role_name:
    description:
      - The name of the role. Required when C(state=present)
    type: str
  lock_user:
    description:
      - Whether the specified user account is locked.
    type: bool
  vserver:
    description:
      - The name of the vserver to use.
      - Required with ZAPI.
      - With REST, ignore this option for creating cluster scoped user account.
    aliases:
      - svm
    type: str
  authentication_protocol:
    description:
      - Authentication protocol for the snmp user.
      - When cluster FIPS mode is on, 'sha' and 'sha2-256' are the only possible and valid values.
      - When cluster FIPS mode is off, the default value is 'none'.
      - When cluster FIPS mode is on, the default value is 'sha'.
      - Only available for 'usm' authentication method and non modifiable.
    choices: ['none', 'md5', 'sha', 'sha2-256']
    type: str
    version_added: '20.6.0'
  authentication_password:
    description:
      - Password for the authentication protocol. This should be minimum 8 characters long.
      - This is required for 'md5', 'sha' and 'sha2-256' authentication protocols and not required for 'none'.
      - Only available for 'usm' authentication method and non modifiable.
    type: str
    version_added: '20.6.0'
  engine_id:
    description:
      - Authoritative entity's EngineID for the SNMPv3 user.
      - This should be specified as a hexadecimal string.
      - Engine ID with first bit set to 1 in first octet should have a minimum of 5 or maximum of 32 octets.
      - Engine Id with first bit set to 0 in the first octet should be 12 octets in length.
      - Engine Id cannot have all zeros in its address.
      - Only available for 'usm' authentication method and non modifiable.
    type: str
    version_added: '20.6.0'
  privacy_protocol:
    description:
      - Privacy protocol for the snmp user.
      - When cluster FIPS mode is on, 'aes128' is the only possible and valid value.
      - When cluster FIPS mode is off, the default value is 'none'. When cluster FIPS mode is on, the default value is 'aes128'.
      - Only available for 'usm' authentication method and non modifiable.
    choices: ['none', 'des', 'aes128']
    type: str
    version_added: '20.6.0'
  privacy_password:
    description:
      - Password for the privacy protocol. This should be minimum 8 characters long.
      - This is required for 'des' and 'aes128' privacy protocols and not required for 'none'.
      - Only available for 'usm' authentication method and non modifiable.
    type: str
    version_added: '20.6.0'
  remote_switch_ipaddress:
    description:
      - This optionally specifies the IP Address of the remote switch.
      - The remote switch could be a cluster switch monitored by Cluster Switch Health Monitor (CSHM)
        or a Fiber Channel (FC) switch monitored by Metro Cluster Health Monitor (MCC-HM).
      - This is applicable only for a remote SNMPv3 user i.e. only if user is a remote (non-local) user,
        application is snmp and authentication method is usm.
    type: str
    version_added: '20.6.0'
  replace_existing_apps_and_methods:
    description:
      - If the user already exists, the current applications and authentications methods are replaced when state=present.
      - If the user already exists, the current applications and authentications methods are removed when state=absent.
      - When using application_dicts or REST, this the only supported behavior.
      - When using application_strs and ZAPI, this is the behavior when this option is set to always.
      - When using application_strs and ZAPI, if the option is set to auto, applications that are not listed are not removed.
      - When using application_strs and ZAPI, if the option is set to auto, authentication mehods that are not listed are not removed.
      - C(auto) preserve the existing behavior for backward compatibility, but note that REST and ZAPI have inconsistent behavior.
      - This is another reason to recommend to use C(application_dicts).
    type: str
    choices: ['always', 'auto']
    default: 'auto'
    version_added: '20.6.0'
'''

EXAMPLES = """
- name: Create User
  netapp.ontap.na_ontap_user:
    state: present
    name: SampleUser
    applications: ssh,console
    authentication_method: password
    set_password: apn1242183u1298u41
    lock_user: true
    role_name: vsadmin
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create cluster scoped user in REST.
  netapp.ontap.na_ontap_user:
    state: present
    name: SampleUser
    applications: ssh,console
    authentication_method: password
    set_password: apn1242183u1298u41
    lock_user: true
    role_name: admin
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete User
  netapp.ontap.na_ontap_user:
    state: absent
    name: SampleUser
    applications: ssh
    authentication_method: password
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create user with snmp application (ZAPI)
  netapp.ontap.na_ontap_user:
    state: present
    name: test_cert_snmp
    applications: snmp
    authentication_method: usm
    role_name: admin
    authentication_protocol: md5
    authentication_password: '12345678'
    privacy_protocol: 'aes128'
    privacy_password: '12345678'
    engine_id: '7063514941000000000000'
    remote_switch_ipaddress: 10.0.0.0
    vserver: "{{ vserver }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create user
  netapp.ontap.na_ontap_user:
    state: present
    name: test123
    application_dicts:
      - application: http
        authentication_methods: password
      - application: ssh
        authentication_methods: password,publickey
    role_name: vsadmin
    set_password: bobdole1234566
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


class NetAppOntapUser:
    """
    Common operations to manage users and roles.
    """

    def __init__(self):
        self.use_rest = False
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),

            application_strs=dict(type='list', elements='str', aliases=['application', 'applications'],
                                  choices=['console', 'http', 'ontapi', 'rsh', 'snmp',
                                           'sp', 'service-processor', 'service_processor', 'ssh', 'telnet'],),
            application_dicts=dict(type='list', elements='dict',
                                   options=dict(
                                       application=dict(required=True, type='str',
                                                        choices=['console', 'http', 'ontapi', 'rsh', 'snmp',
                                                                 'sp', 'service-processor', 'service_processor', 'ssh', 'telnet'],),
                                       authentication_methods=dict(required=True, type='list', elements='str',
                                                                   choices=['community', 'password', 'publickey', 'domain', 'nsswitch', 'usm', 'cert', 'saml']),
                                       second_authentication_method=dict(type='str', choices=['none', 'password', 'publickey', 'nsswitch', 'totp']))),
            authentication_method=dict(type='str',
                                       choices=['community', 'password', 'publickey', 'domain', 'nsswitch', 'usm', 'cert', 'saml']),
            set_password=dict(type='str', no_log=True),
            role_name=dict(type='str'),
            lock_user=dict(type='bool'),
            vserver=dict(type='str', aliases=['svm']),
            authentication_protocol=dict(type='str', choices=['none', 'md5', 'sha', 'sha2-256']),
            authentication_password=dict(type='str', no_log=True),
            engine_id=dict(type='str'),
            privacy_protocol=dict(type='str', choices=['none', 'des', 'aes128']),
            privacy_password=dict(type='str', no_log=True),
            remote_switch_ipaddress=dict(type='str'),
            replace_existing_apps_and_methods=dict(type='str', choices=['always', 'auto'], default='auto')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            mutually_exclusive=[
                ('application_strs', 'application_dicts')
            ],
            required_together=[
                ('application_strs', 'authentication_method')
            ],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.strs_to_dicts()

        # REST API should be used for ONTAP 9.6 or higher
        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        # some attributes are not supported in earlier REST implementation
        unsupported_rest_properties = ['authentication_password', 'authentication_protocol', 'engine_id',
                                       'privacy_password', 'privacy_protocol']
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties)
        if not self.use_rest:
            if self.parameters.get('vserver') is None:
                self.module.fail_json(msg="Error: vserver is required with ZAPI")
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])
        self.validate_applications()

    def validate_applications(self):
        if not self.use_rest:
            if self.parameters['applications'] is None:
                self.module.fail_json(msg="application_dicts or application_strs is a required parameter with ZAPI")
            for application in self.parameters['applications']:
                if application['application'] == 'service_processor':
                    application['application'] = 'service-processor'
        if self.parameters['applications'] is None:
            return
        application_keys = []
        for application in self.parameters['applications']:
            # make sure app entries are not duplicated
            application_name = application['application']
            if application_name in application_keys:
                self.module.fail_json(msg='Error: repeated application name: %s.  Group all authentication methods under a single entry.' % application_name)
            application_keys.append(application_name)
            if self.use_rest:
                if application_name == 'snmp':
                    self.module.fail_json(msg="snmp as application is not supported in REST.")
                # REST prefers certificate to cert
                application['authentication_methods'] = ['certificate' if x == 'cert' else x for x in application['authentication_methods']]
                # REST get always returns 'second_authentication_method'
                if 'second_authentication_method' not in application:
                    application['second_authentication_method'] = None

    def strs_to_dicts(self):
        """transform applications list of strs to a list of dicts if application_strs in use"""
        if 'application_dicts' in self.parameters:
            for application in self.parameters['application_dicts']:
                # keep them sorted for comparison with current
                application['authentication_methods'].sort()
            self.parameters['applications'] = self.parameters['application_dicts']
            self.parameters['replace_existing_apps_and_methods'] = 'always'
        elif 'application_strs' in self.parameters:
            # actual conversion
            self.parameters['applications'] = [
                dict(application=application,
                     authentication_methods=[self.parameters['authentication_method']],
                     second_authentication_method=None
                     ) for application in self.parameters['application_strs']]
        else:
            self.parameters['applications'] = None

    def get_user_rest(self):
        api = 'security/accounts'
        query = {
            'name': self.parameters['name']
        }
        if self.parameters.get('vserver') is None:
            # vserser is empty for cluster
            query['scope'] = 'cluster'
        else:
            query['owner.name'] = self.parameters['vserver']

        message, error = self.rest_api.get(api, query)
        if error:
            self.module.fail_json(msg='Error while fetching user info: %s' % error)
        if message['num_records'] == 1:
            return message['records'][0]['owner']['uuid'], message['records'][0]['name']
        if message['num_records'] > 1:
            self.module.fail_json(msg='Error while fetching user info, found multiple entries: %s' % repr(message))

        return None

    def get_user_details_rest(self, name, owner_uuid):
        query = {
            'fields': 'role,applications,locked'
        }
        api = "security/accounts/%s/%s" % (owner_uuid, name)
        response, error = self.rest_api.get(api, query)
        if error:
            self.module.fail_json(msg='Error while fetching user details: %s' % error)
        if response:
            # replace "none" values with None for comparison
            for application in response['applications']:
                if application.get('second_authentication_method') == 'none':
                    application['second_authentication_method'] = None
                # new read-only attributes in 9.14 onwards, breaks idempotency when present
                application.pop('is_ldap_fastbind', None)
                application.pop('is_ns_switch_group', None)
            return_value = {
                'role_name': response['role']['name'],
                'applications': response['applications']
            }
            if "locked" in response:
                return_value['lock_user'] = response['locked']
        return return_value

    def get_user(self):
        """
        Checks if the user exists.
        :param: application: application to grant access to, a dict
        :return:
            Dictionary if user found
            None if user is not found
        """
        desired_applications = [application['application'] for application in self.parameters['applications']]
        desired_method = self.parameters.get('authentication_method')
        security_login_get_iter = netapp_utils.zapi.NaElement('security-login-get-iter')
        query_details = netapp_utils.zapi.NaElement.create_node_with_children(
            'security-login-account-info', **{'vserver': self.parameters['vserver'],
                                              'user-name': self.parameters['name']})

        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(query_details)
        security_login_get_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(security_login_get_iter,
                                                     enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            if to_native(error.code) in ['16034', '16043']:
                # Error 16034 denotes a user not being found.
                # Error 16043 denotes the user existing, but the application missing.
                return None
            self.module.fail_json(msg='Error getting user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

        if not result.get_child_by_name('num-records') or not int(result.get_child_content('num-records')):
            return None

        applications = {}
        attr = result.get_child_by_name('attributes-list')
        locks = []
        for info in attr.get_children():
            lock_user = self.na_helper.get_value_for_bool(True, info.get_child_content('is-locked'))
            locks.append(lock_user)
            role_name = info.get_child_content('role-name')
            application = info.get_child_content('application')
            auth_method = info.get_child_content('authentication-method')
            sec_method = info.get_child_content('second-authentication-method')
            if self.parameters['replace_existing_apps_and_methods'] == 'always' and application in applications:
                applications[application][0].append(auth_method)
                if sec_method != 'none':
                    # we can't change sec_method in place, a tuple is not mutable
                    applications[application] = (applications[application][0], sec_method)
            elif (self.parameters['replace_existing_apps_and_methods'] == 'always'
                  or (application in desired_applications and auth_method == desired_method)):
                # with 'auto' we ignore existing apps that were not asked for
                # with auto, only a single method is supported
                applications[application] = ([auth_method], sec_method if sec_method != 'none' else None)
        apps = [dict(application=application, authentication_methods=sorted(methods), second_authentication_method=sec_method)
                for application, (methods, sec_method) in applications.items()]
        return dict(
            lock_user=any(locks),
            role_name=role_name,
            applications=apps
        )

    def create_user_rest(self, apps):
        api = 'security/accounts'
        body = {
            'name': self.parameters['name'],
            'role.name': self.parameters['role_name'],
            'applications': self.na_helper.filter_out_none_entries(apps)
        }
        if self.parameters.get('vserver') is not None:
            # vserser is empty for cluster
            body['owner.name'] = self.parameters['vserver']
        if 'set_password' in self.parameters:
            body['password'] = self.parameters['set_password']
        if 'lock_user' in self.parameters:
            body['locked'] = self.parameters['lock_user']
        dummy, error = self.rest_api.post(api, body)
        if (
            error
            and 'invalid value' in error['message']
            and any(x in error['message'] for x in ['service-processor', 'service_processor'])
        ):
            # find if there is an error for service processor application value
            # update value as per ONTAP version support
            app_list_sp = body['applications']
            for app_item in app_list_sp:
                if app_item['application'] == 'service-processor':
                    app_item['application'] = 'service_processor'
                elif app_item['application'] == 'service_processor':
                    app_item['application'] = 'service-processor'
            body['applications'] = app_list_sp
            # post again and throw first error in case of an error
            dummy, error_sp = self.rest_api.post(api, body)
            if not error_sp:
                return

        # non-sp errors thrown or initial sp errors
        if error:
            self.module.fail_json(msg='Error while creating user: %s' % error)

    def create_user(self, application):
        for index in range(len(application['authentication_methods'])):
            self.create_user_with_auth(application, index)

    def create_user_with_auth(self, application, index):
        """
        creates the user for the given application and authentication_method
        application is now a directory
        :param: application: application to grant access to
        """
        user_create = netapp_utils.zapi.NaElement.create_node_with_children(
            'security-login-create', **{'vserver': self.parameters['vserver'],
                                        'user-name': self.parameters['name'],
                                        'application': application['application'],
                                        'authentication-method': application['authentication_methods'][index],
                                        'role-name': self.parameters.get('role_name')})
        if application.get('second_authentication_method') is not None:
            user_create.add_new_child('second-authentication-method', application['second_authentication_method'])
        if self.parameters.get('set_password') is not None:
            user_create.add_new_child('password', self.parameters.get('set_password'))
        if application['authentication_methods'][0] == 'usm':
            if self.parameters.get('remote_switch_ipaddress') is not None:
                user_create.add_new_child('remote-switch-ipaddress', self.parameters.get('remote_switch_ipaddress'))
            snmpv3_login_info = netapp_utils.zapi.NaElement('snmpv3-login-info')
            if self.parameters.get('authentication_password') is not None:
                snmpv3_login_info.add_new_child('authentication-password', self.parameters['authentication_password'])
            if self.parameters.get('authentication_protocol') is not None:
                snmpv3_login_info.add_new_child('authentication-protocol', self.parameters['authentication_protocol'])
            if self.parameters.get('engine_id') is not None:
                snmpv3_login_info.add_new_child('engine-id', self.parameters['engine_id'])
            if self.parameters.get('privacy_password') is not None:
                snmpv3_login_info.add_new_child('privacy-password', self.parameters['privacy_password'])
            if self.parameters.get('privacy_protocol') is not None:
                snmpv3_login_info.add_new_child('privacy-protocol', self.parameters['privacy_protocol'])
            user_create.add_child_elem(snmpv3_login_info)

        try:
            self.server.invoke_successfully(user_create,
                                            enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def lock_unlock_user_rest(self, owner_uuid, username, value=None):
        body = {
            'locked': value
        }
        error = self.patch_account(owner_uuid, username, body)
        if error:
            self.module.fail_json(msg='Error while locking/unlocking user: %s' % error)

    def lock_given_user(self):
        """
        locks the user
        """
        user_lock = netapp_utils.zapi.NaElement.create_node_with_children(
            'security-login-lock', **{'vserver': self.parameters['vserver'],
                                      'user-name': self.parameters['name']})

        try:
            self.server.invoke_successfully(user_lock,
                                            enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error locking user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def unlock_given_user(self):
        """
        unlocks the user
        """
        user_unlock = netapp_utils.zapi.NaElement.create_node_with_children(
            'security-login-unlock', **{'vserver': self.parameters['vserver'],
                                        'user-name': self.parameters['name']})

        try:
            self.server.invoke_successfully(user_unlock,
                                            enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            if to_native(error.code) != '13114':
                self.module.fail_json(msg='Error unlocking user %s: %s' % (self.parameters['name'], to_native(error)),
                                      exception=traceback.format_exc())
        return

    def delete_user_rest(self, owner_uuid, username):
        api = "security/accounts/%s/%s" % (owner_uuid, username)
        dummy, error = self.rest_api.delete(api)
        if error:
            self.module.fail_json(msg='Error while deleting user: %s' % error)

    def delete_user(self, application, methods_to_keep=None):
        for index, method in enumerate(application['authentication_methods']):
            if methods_to_keep is None or method not in methods_to_keep:
                self.delete_user_with_auth(application, index)

    def delete_user_with_auth(self, application, index):
        """
        deletes the user for the given application and authentication_method
        application is now a dict
        :param: application: application to grant access to
        """
        user_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'security-login-delete', **{'vserver': self.parameters['vserver'],
                                        'user-name': self.parameters['name'],
                                        'application': application['application'],
                                        'authentication-method': application['authentication_methods'][index]})

        try:
            self.server.invoke_successfully(user_delete,
                                            enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error removing user %s: %s - application: %s'
                                  % (self.parameters['name'], to_native(error), application),
                                  exception=traceback.format_exc())

    @staticmethod
    def is_repeated_password(message):
        return message.startswith('New password must be different than last 6 passwords.') \
            or message.startswith('New password must be different from last 6 passwords.') \
            or message.startswith('New password must be different than the old password.') \
            or message.startswith('New password must be different from the old password.')

    def change_password_rest(self, owner_uuid, username):
        body = {
            'password': self.parameters['set_password'],
        }
        error = self.patch_account(owner_uuid, username, body)
        if error:
            if 'message' in error and self.is_repeated_password(error['message']):
                # if the password is reused, assume idempotency but show a warning
                self.module.warn('Password was not changed: %s' % error['message'])
                return False
            self.module.fail_json(msg='Error while updating user password: %s' % error)
        return True

    def change_password(self):
        """
        Changes the password

        :return:
            True if password updated
            False if password is not updated
        :rtype: bool
        """
        # self.server.set_vserver(self.parameters['vserver'])
        modify_password = netapp_utils.zapi.NaElement.create_node_with_children(
            'security-login-modify-password', **{
                'new-password': str(self.parameters.get('set_password')),
                'user-name': self.parameters['name']})
        try:
            self.server.invoke_successfully(modify_password,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if to_native(error.code) == '13114':
                return False
            # if the user give the same password, instead of returning an error, return ok
            if to_native(error.code) == '13214' and self.is_repeated_password(error.message):
                return False
            self.module.fail_json(msg='Error setting password for user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

        self.server.set_vserver(None)
        return True

    def modify_apps_rest(self, owner_uuid, username, apps=None):
        body = {
            'role.name': self.parameters['role_name'],
            'applications': self.na_helper.filter_out_none_entries(apps)
        }
        error = self.patch_account(owner_uuid, username, body)
        if error:
            self.module.fail_json(msg='Error while modifying user details: %s' % error)

    def patch_account(self, owner_uuid, username, body):
        query = {'name': self.parameters['name'], 'owner.uuid': owner_uuid}
        api = "security/accounts/%s/%s" % (owner_uuid, username)
        dummy, result = self.rest_api.patch(api, body, query)
        return result

    def modify_user(self, application, current_methods):
        for index, method in enumerate(application['authentication_methods']):
            if method in current_methods:
                self.modify_user_with_auth(application, index)
            else:
                self.create_user_with_auth(application, index)

    def modify_user_with_auth(self, application, index):
        """
        Modify user
        application is now a dict
        """
        user_modify = netapp_utils.zapi.NaElement.create_node_with_children(
            'security-login-modify', **{'vserver': self.parameters['vserver'],
                                        'user-name': self.parameters['name'],
                                        'application': application['application'],
                                        'authentication-method': application['authentication_methods'][index],
                                        'role-name': self.parameters.get('role_name')})

        try:
            self.server.invoke_successfully(user_modify,
                                            enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying user %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def change_sp_application(self, current_apps):
        """Adjust requested app name to match ONTAP convention"""
        if not self.parameters['applications']:
            return
        app_list = [app['application'] for app in current_apps]
        for application in self.parameters['applications']:
            if application['application'] == 'service_processor' and 'service-processor' in app_list:
                application['application'] = 'service-processor'
            elif application['application'] == 'service-processor' and 'service_processor' in app_list:
                application['application'] = 'service_processor'

    def validate_action(self, action):
        errors = []
        if action == 'create':
            if not self.parameters.get('role_name'):
                errors.append('role_name')
            if not self.parameters.get('applications'):
                errors.append('application_dicts or application_strs')
        if errors:
            plural = 's' if len(errors) > 1 else ''
            self.module.fail_json(msg='Error: missing required parameter%s for %s: %s.' %
                                  (plural, action, ' and: '.join(errors)))

    def modify_apps_zapi(self, current, modify_decision):
        if 'applications' not in modify_decision:
            # to change roles, we need at least one app
            modify_decision['applications'] = self.parameters['applications']
        current_apps = dict((application['application'], application['authentication_methods']) for application in current['applications'])
        for application in modify_decision['applications']:
            if application['application'] in current_apps:
                self.modify_user(application, current_apps[application['application']])
            else:
                self.create_user(application)
        desired_apps = dict((application['application'], application['authentication_methods'])
                            for application in self.parameters['applications'])
        for application in current['applications']:
            if application['application'] not in desired_apps:
                self.delete_user(application)
            else:
                self.delete_user(application, desired_apps[application['application']])

    def get_current(self):
        owner_uuid, name = None, None
        if self.use_rest:
            current = self.get_user_rest()
            if current is not None:
                owner_uuid, name = current
                current = self.get_user_details_rest(name, owner_uuid)
                self.change_sp_application(current['applications'])
        else:
            current = self.get_user()
        return current, owner_uuid, name

    def define_actions(self, current):
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.na_helper.get_modified_attributes(current, self.parameters) if cd_action is None else None
        if self.use_rest and cd_action is None and current and 'lock_user' not in current and self.parameters.get('lock_user') is not None:
            # REST does not return locked if password is not set
            if self.parameters.get('set_password') is None:
                self.module.fail_json(msg='Error: cannot modify lock state if password is not set.')
            modify['lock_user'] = self.parameters['lock_user']
            self.na_helper.changed = True
        self.validate_action(cd_action)
        return cd_action, modify

    def take_action(self, cd_action, modify, current, owner_uuid, name):
        if cd_action == 'create':
            if self.use_rest:
                self.create_user_rest(self.parameters['applications'])
            else:
                for application in self.parameters['applications']:
                    self.create_user(application)
        elif cd_action == 'delete':
            if self.use_rest:
                self.delete_user_rest(owner_uuid, name)
            else:
                for application in current['applications']:
                    self.delete_user(application)
        elif modify:
            if 'role_name' in modify or 'applications' in modify:
                if self.use_rest:
                    self.modify_apps_rest(owner_uuid, name, self.parameters['applications'])
                else:
                    self.modify_apps_zapi(current, modify)
        return modify and 'lock_user' in modify

    def apply(self):
        current, owner_uuid, name = self.get_current()
        cd_action, modify = self.define_actions(current)
        deferred_lock = False

        if self.na_helper.changed and not self.module.check_mode:
            # lock/unlock actions require password to be set
            deferred_lock = self.take_action(cd_action, modify, current, owner_uuid, name)

        password_changed = False
        if cd_action is None and self.parameters.get('set_password') is not None and self.parameters['state'] == 'present':
            # if check_mode, don't attempt to change the password, but assume it would be changed
            if self.use_rest:
                password_changed = self.module.check_mode or self.change_password_rest(owner_uuid, name)
            else:
                password_changed = self.module.check_mode or self.change_password()
            if self.module.check_mode:
                self.module.warn('Module is not idempotent with check_mode when set_password is present.')

        if deferred_lock:
            if self.use_rest:
                self.lock_unlock_user_rest(owner_uuid, name, self.parameters['lock_user'])
            elif self.parameters.get('lock_user'):
                self.lock_given_user()
            else:
                self.unlock_given_user()

        self.module.exit_json(changed=self.na_helper.changed | password_changed, current=current, modify=modify)


def main():
    obj = NetAppOntapUser()
    obj.apply()


if __name__ == '__main__':
    main()
