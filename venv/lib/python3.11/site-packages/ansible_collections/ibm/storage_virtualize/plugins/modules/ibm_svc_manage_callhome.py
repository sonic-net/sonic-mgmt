#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 IBM CORPORATION
# Author(s): Sreshtant Bohidar <sreshtant.bohidar@ibm.com>
#            Sandip Gulab Rajbanshi <sandip.rajbanshi@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_manage_callhome
short_description: This module manages Call Home feature configuration on IBM Storage Virtualize
                   family systems
description:
  - Ansible interface to manage cloud and email Call Home feature.
version_added: "1.7.0"
options:
    state:
        description:
            - Enables or updates (C(enabled)) or disables (C(disabled)) Call Home feature.
        choices: [ enabled, disabled ]
        required: true
        type: str
    clustername:
        description:
            - The hostname or management IP of the Storage Virtualize system.
        type: str
        required: true
    domain:
        description:
            - Domain for the Storage Virtualize system.
            - Valid when hostname is used for the parameter I(clustername).
        type: str
    username:
        description:
            - REST API username for the Storage Virtualize system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    password:
        description:
            - REST API password for the Storage Virtualize system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    token:
        description:
            - The authentication token to verify a user on the Storage Virtualize system.
            - To generate a token, use the ibm_svc_auth module.
        type: str
    callhome_type:
        description:
            - Specifies the transmission type.
        choices: [ 'cloud services', 'email', 'both' ]
        required: True
        type: str
    proxy_type:
        description:
            - Specifies the proxy type.
            - Required when I(state=enabled), to create or modify Call Home feature.
            - Proxy gets deleted for I(proxy_type=no_proxy).
            - The parameter is mandatory when I(callhome_type='cloud services')) or I(callhome_type='both').
        choices: [ open_proxy, basic_authentication, certificate, no_proxy ]
        type: str
    proxy_url:
        description:
            - Specifies the proxy server URL with a protocol prefix in fully qualified domain name format.
            - Applies when I(state=enabled) and I(proxy_type=open_proxy) or I(proxy_type=basic_authentication).
        type: str
    proxy_port:
        description:
            - Specifies the proxy server port number.
              The value must be in the range 1 - 65535.
            - Applies when I(state=enabled) and I(proxy_type=open_proxy) or I(proxy_type=basic_authentication).
        type: int
    proxy_username:
        description:
            - Specifies the proxy's username.
            - Applies when I(state=enabled) and I(proxy_type=basic_authentication).
        type: str
    proxy_password:
        description:
            - Specifies the proxy's password.
            - Applies when I(state=enabled) and I(proxy_type=basic_authentication).
        type: str
    sslcert:
        description:
            - Specifies the file path of proxy's certificate.
            - Applies when I(state=enabled) and I(proxy_type=certificate).
        type: str
    company_name:
        description:
            - Specifies the user's organization as it should appear in Call Home email.
            - Required when I(state=enabled).
        type: str
    address:
        description:
            - Specifies the first line of the user's address as it should appear in Call Home email.
            - Required when I(state=enabled).
        type: str
    city:
        description:
            - Specifies the user's city as it should appear in Call Home email.
            - Required when I(state=enabled).
        type: str
    province:
        description:
            - Specifies the user's state or province as it should appear in Call Home email.
            - Required when I(state=enabled).
        type: str
    postalcode:
        description:
            - Specifies the user's zip code or postal code as it should appear in Call Home email.
            - Required when I(state=enabled).
        type: str
    country:
        description:
            - Specifies the country in which the machine resides as it should appear in Call Home email.
            - Required when I(state=enabled).
        type: str
    location:
        description:
            - Specifies the physical location of the system that has reported the error.
            - Required when I(state=enabled).
        type: str
    contact_name:
        description:
            - Specifies the name of the person receiving the email.
            - Required when I(state=enabled).
        type: str
    contact_email:
        description:
            - Specifies the email of the person.
            - Required when I(state=enabled).
        type: str
    phonenumber_primary:
        description:
            - Specifies the primary contact telephone number.
            - Required when I(state=enabled).
        type: str
    phonenumber_secondary:
        description:
            - Specifies the secondary contact telephone number.
            - Required when I(state=enabled).
        type: str
    serverIP:
        description:
            - Specifies the IP address of the email server.
            - Required when I(state=enabled) and I(callhome_type=email) or I(callhome_type=both).
        type: str
    serverPort:
        description:
            - Specifies the port number of the email server.
            - The value must be in the range 1 - 65535.
            - Required when I(state=enabled) and I(callhome_type=email) or I(callhome_type=both).
        type: int
    inventory:
        description:
            - Specifies whether the recipient mentioned in parameter I(contact_email) receives inventory email notifications.
            - Applies when I(state=enabled).
              If unspecified, default value 'off' will be used.
        choices: ['on', 'off']
        type: str
    invemailinterval:
        description:
            - Specifies the interval at which inventory emails are sent to the configured email recipients.
            - The interval is measured in days. The value must be in the range 0 - 15.
            - Setting the value to '0' turns off the inventory email notification function.
              Valid if I(inventory) is set to 'on'.
        type: int
    enhancedcallhome:
        description:
            - Specifies that the Call Home function is to send enhanced reports to the support center.
            - Applies when I(state=enabled).
            - If unspecified, default value 'off' will be used.
        choices: ['on', 'off']
        type: str
    censorcallhome:
        description:
            - Specifies that sensitive data is deleted from the enhanced Call Home data.
            - Applies when I(state=enabled).
            - If unspecified, default value 'off' will be used.
        choices: ['on', 'off']
        type: str
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
    log_path:
        description:
            - Path of debug log file.
        type: str
author:
    - Sreshtant Bohidar(@Sreshtant-Bohidar)
    - Sandip Gulab Rajbanshi (@Sandip-Rajbanshi)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Configure callhome with both email and cloud
  ibm.storage_virtualize.ibm_svc_manage_callhome:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: "/tmp/playbook.debug"
    state: "enabled"
    callhome_type: "both"
    address: "{{ address }}"
    city: "{{ city }}"
    company_name: "{{ company_name }}"
    contact_email: "{{ contact_email }}"
    contact_name: "{{ contact_name }}"
    country: "{{ country }}"
    location: "{{ location }}"
    phonenumber_primary: "{{ primary_phonenumber }}"
    postalcode: "{{ postal_code }}"
    province: "{{ province }}"
    proxy_type: "{{ proxy_type }}"
    proxy_url: "{{ proxy_url }}"
    proxy_port: "{{ proxy_port }}"
    serverIP: "{{ server_ip }}"
    serverPort: "{{ server_port }}"
    inventory: "on"
    invemailinterval: 1
    enhancedcallhome: "on"
    censorcallhome: "on"

- name: Configure callhome with cloud
  ibm.storage_virtualize.ibm_svc_manage_callhome:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: "/tmp/playbook.debug"
    state: "enabled"
    callhome_type: "cloud services"
    province: "{{ province }}"
    proxy_type: "{{ proxy_type }}"
    proxy_url: "{{ proxy_url }}"
    proxy_port: "{{ proxy_port }}"

- name: Configure callhome with email
  ibm.storage_virtualize.ibm_svc_manage_callhome:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: "/tmp/playbook.debug"
    state: "enabled"
    callhome_type: "email"
    contact_email: "{{ contact_email }}"
    serverIP: "{{ server_ip }}"
    serverPort: "{{ server_port }}"
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native
import time


class IBMSVCCallhome(object):
    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                state=dict(type='str', required=True, choices=['enabled', 'disabled']),
                callhome_type=dict(type='str', required=True, choices=['cloud services', 'email', 'both']),
                proxy_type=dict(type='str', choices=['open_proxy', 'basic_authentication', 'certificate', 'no_proxy']),
                proxy_url=dict(type='str'),
                proxy_port=dict(type='int'),
                proxy_username=dict(type='str'),
                proxy_password=dict(type='str', no_log=True),
                sslcert=dict(type='str'),
                company_name=dict(type='str'),
                address=dict(type='str'),
                city=dict(type='str'),
                province=dict(type='str'),
                postalcode=dict(type='str'),
                country=dict(type='str'),
                location=dict(type='str'),
                contact_name=dict(type='str'),
                contact_email=dict(type='str'),
                phonenumber_primary=dict(type='str'),
                phonenumber_secondary=dict(type='str'),
                serverIP=dict(type='str'),
                serverPort=dict(type='int'),
                inventory=dict(type='str', choices=['on', 'off']),
                invemailinterval=dict(type='int'),
                enhancedcallhome=dict(type='str', choices=['on', 'off']),
                censorcallhome=dict(type='str', choices=['on', 'off'])
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required
        self.state = self.module.params['state']
        self.callhome_type = self.module.params['callhome_type']

        # Optional
        self.company_name = self.module.params['company_name']
        self.address = self.module.params['address']
        self.city = self.module.params['city']
        self.province = self.module.params['province']
        self.postalcode = self.module.params['postalcode']
        self.country = self.module.params['country']
        self.location = self.module.params['location']
        self.contact_name = self.module.params['contact_name']
        self.contact_email = self.module.params['contact_email']
        self.phonenumber_primary = self.module.params['phonenumber_primary']
        self.proxy_type = self.module.params.get('proxy_type', False)
        self.proxy_url = self.module.params.get('proxy_url', False)
        self.proxy_port = self.module.params.get('proxy_port', False)
        self.proxy_username = self.module.params.get('proxy_username', False)
        self.proxy_password = self.module.params.get('proxy_password', False)
        self.sslcert = self.module.params.get('sslcert', False)
        self.phonenumber_secondary = self.module.params.get('phonenumber_secondary', False)
        self.serverIP = self.module.params.get('serverIP', False)
        self.serverPort = self.module.params.get('serverPort', False)
        self.inventory = self.module.params.get('inventory', False)
        self.invemailinterval = self.module.params.get('invemailinterval', False)
        self.enhancedcallhome = self.module.params.get('enhancedcallhome', False)
        self.censorcallhome = self.module.params.get('censorcallhome', False)

        # creating an instance of IBMSVCRestApi
        self.restapi = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.module.params['domain'],
            username=self.module.params['username'],
            password=self.module.params['password'],
            validate_certs=self.module.params['validate_certs'],
            log_path=log_path,
            token=self.module.params['token']
        )

    def basic_checks(self):
        # setting the default value if unspecified
        if not self.inventory:
            self.inventory = 'off'
        if not self.enhancedcallhome:
            self.enhancedcallhome = 'off'
        if not self.censorcallhome:
            self.censorcallhome = 'off'
        # perform some basic handling for few parameters
        if self.inventory == 'on':
            if not self.invemailinterval:
                self.module.fail_json(msg="Parameter [invemailinterval] should be configured to use [inventory]")
        if self.invemailinterval:
            if self.inventory == 'off':
                self.module.fail_json(msg="The parameter [inventory] should be configured with 'on' while setting [invemailinterval]")
            if self.invemailinterval not in range(1, 16):
                self.module.fail_json(msg="Parameter [invemailinterval] supported range is 0 to 15")
        if isinstance(self.serverPort, int):
            if self.serverPort not in range(1, 65536):
                self.module.fail_json(msg="Parameter [serverPort] must be in range[1-65535]")
        if isinstance(self.proxy_port, int):
            if self.proxy_port not in range(1, 65536):
                self.module.fail_json(msg="Parameter [proxy_port] must be in range[1-65535]")
        if not self.state:
            self.module.fail_json(msg="Missing mandatory parameter: state")
        if not self.callhome_type:
            self.module.fail_json(msg="Missing mandatory parameter: callhome_type")
        if self.state == "enabled" and self.callhome_type in ["cloud services", "both"]:
            if not self.proxy_type:
                self.module.fail_json(msg="Parameter [proxy_type] required when callhome_type=cloud services or both")
            if self.proxy_type == 'open_proxy' and (not self.proxy_url or not self.proxy_port):
                self.module.fail_json(msg="Parameters [proxy_url, proxy_port] required when proxy_type=open_proxy")
            if self.proxy_type == 'basic_authentication' and (not self.proxy_url or not self.proxy_port or not self.proxy_username or not self.proxy_password):
                self.module.fail_json(msg="Parameters [proxy_url, proxy_port, proxy_username, proxy_password] required when proxy_type=basic_authentication")
            if self.proxy_type == 'certificate' and (not self.proxy_url or not self.proxy_port or not self.sslcert):
                self.module.fail_json(msg="Parameters [proxy_url, proxy_port, sslcert] required when proxy_type=certificate")
        if self.state == 'enabled' and self.callhome_type in ["email", "both"]:
            parameters = {
                'contact_email': self.contact_email,
                'serverIP': self.serverIP,
                'serverPort': self.serverPort
            }
            parameter_not_provided = []
            for parameter in parameters:
                if not parameters[parameter]:
                    parameter_not_provided.append(parameter)
            if parameter_not_provided:
                self.module.fail_json(msg="Parameters {0} are required when state is 'enabled' and"
                                      " callhome_type is email or both".format(parameter_not_provided))

    # function to fetch lssystem data
    def get_system_data(self):
        return self.restapi.svc_obj_info('lssystem', cmdopts=None, cmdargs=None)

    # function to probe lssystem data
    def probe_system(self, data):
        modify = {}
        if self.invemailinterval:
            if self.invemailinterval != data['inventory_mail_interval']:
                modify['invemailinterval'] = self.invemailinterval
        if self.enhancedcallhome:
            if self.enhancedcallhome != data['enhanced_callhome']:
                modify['enhancedcallhome'] = self.enhancedcallhome
        if self.censorcallhome:
            if self.censorcallhome != data['censor_callhome']:
                modify['censorcallhome'] = self.censorcallhome
        return modify

    # function to execute chsystem commands
    def update_system(self, modify):
        command = 'chsystem'
        command_options = modify
        cmdargs = None
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.log("Chsystem commands executed.")

    # function to fetch existing email user
    def get_existing_email_user_data(self):
        data = {}
        email_data = self.restapi.svc_obj_info(cmd='lsemailuser', cmdopts=None, cmdargs=None)
        for item in email_data:
            if item['address'] == self.contact_email:
                data = item
        return data

    # function to check if email server exists or not
    def check_email_server_exists(self):
        status = False
        data = self.restapi.svc_obj_info(cmd='lsemailserver', cmdopts=None, cmdargs=None)
        for item in data:
            if item['IP_address'] == self.serverIP and int(item['port']) == self.serverPort:
                status = True
                break
        return status

    # function to check if email user exists or not
    def check_email_user_exists(self):
        temp = {}
        data = self.restapi.svc_obj_info(cmd='lsemailuser', cmdopts=None, cmdargs=None)
        for item in data:
            if item['address'] == self.contact_email:
                temp = item
                break
        return temp

    # function to create an email server
    def create_email_server(self):
        if self.module.check_mode:
            self.changed = True
            return
        self.log("Creating email server '%s:%s'.", self.serverIP, self.serverPort)
        command = 'mkemailserver'
        command_options = {
            'ip': self.serverIP,
            'port': self.serverPort,
        }
        cmdargs = None
        result = self.restapi.svc_run_command(command, command_options, cmdargs)
        if 'message' in result:
            self.changed = True
            self.log("create email server result message '%s'", (result['message']))
        else:
            self.module.fail_json(
                msg="Failed to create email server [%s:%s]" % (self.serverIP, self.serverPort)
            )

    # function to update email user
    def update_email_user(self, data, id):
        command = "chemailuser"
        command_options = data
        cmdargs = [id]
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.log('Email user updated successfully.')

    # function to manage support email user
    def manage_support_email_user(self):
        if self.module.check_mode:
            self.changed = True
            return
        support_email = {}
        selected_email_id = ''
        t = -1 * ((time.timezone / 60) / 60)
        if t >= -8 and t <= -4:
            # for US timezone, callhome0@de.ibm.com is used
            selected_email_id = 'callhome0@de.ibm.com'
        else:
            # for ROW, callhome1@de.ibm.com is used
            selected_email_id = 'callhome1@de.ibm.com'
        existing_user = self.restapi.svc_obj_info('lsemailuser', cmdopts=None, cmdargs=None)
        if existing_user:
            for user in existing_user:
                if user['user_type'] == 'support':
                    support_email = user
        if not support_email:
            self.log("Creating support email user '%s'.", selected_email_id)
            command = 'mkemailuser'
            command_options = {
                'address': selected_email_id,
                'usertype': 'support',
                'info': 'off',
                'warning': 'off',
            }
            if self.inventory:
                command_options['inventory'] = self.inventory
            cmdargs = None
            result = self.restapi.svc_run_command(command, command_options, cmdargs)
            if 'message' in result:
                self.changed = True
                self.log("create support email user result message '%s'", (result['message']))
            else:
                self.module.fail_json(
                    msg="Failed to support create email user [%s]" % (self.contact_email)
                )
        else:
            modify = {}
            if support_email['address'] != selected_email_id:
                modify['address'] = selected_email_id
            if self.inventory:
                if support_email['inventory'] != self.inventory:
                    modify['inventory'] = self.inventory
            if modify:
                self.restapi.svc_run_command(
                    'chemailuser',
                    modify,
                    [support_email['id']]
                )
                self.log("Updated support user successfully.")

    # function to create an email user
    def create_email_user(self):
        if self.module.check_mode:
            self.changed = True
            return
        self.log("Creating email user '%s'.", self.contact_email)
        command = 'mkemailuser'
        command_options = {
            'address': self.contact_email,
            'usertype': 'local',
        }
        if self.inventory:
            command_options['inventory'] = self.inventory
        cmdargs = None
        result = self.restapi.svc_run_command(command, command_options, cmdargs)
        if 'message' in result:
            self.changed = True
            self.log("Create email user result message '%s'.", (result['message']))
        else:
            self.module.fail_json(
                msg="Failed to create email user [%s]" % (self.contact_email)
            )

    # function to enable email callhome
    def enable_email_callhome(self):
        if self.module.check_mode:
            self.changed = True
            return
        command = "startemail"
        command_options = {}
        cmdargs = None
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.log("Email callhome enabled.")

    # function to disable email callhome
    def disable_email_callhome(self):
        if self.module.check_mode:
            self.changed = True
            return
        command = "stopemail"
        command_options = {}
        cmdargs = None
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.log("Email callhome disabled.")

    # function to update email data
    def update_email_data(self):

        if self.module.check_mode:
            self.changed = True
            return
        command = "chemail"
        command_options = {}
        if self.contact_email:
            command_options['reply'] = self.contact_email
        if self.contact_name:
            command_options['contact'] = self.contact_name
        if self.phonenumber_primary:
            command_options['primary'] = self.phonenumber_primary
        if self.phonenumber_secondary:
            command_options['alternate'] = self.phonenumber_secondary
        if self.location:
            command_options['location'] = self.location
        if self.company_name:
            command_options['organization'] = self.company_name
        if self.address:
            command_options['address'] = self.address
        if self.city:
            command_options['city'] = self.city
        if self.province:
            command_options['state'] = self.province
        if self.postalcode:
            command_options['zip'] = self.postalcode
        if self.country:
            command_options['country'] = self.country
        cmdargs = None
        if command_options:
            self.restapi.svc_run_command(command, command_options, cmdargs)
            self.log("Email data successfully updated.")

    # function for checking if proxy server exists
    def get_existing_proxy(self):
        data = {}
        data = self.restapi.svc_obj_info(cmd='lsproxy', cmdopts=None, cmdargs=None)
        return data

    # function for removing a proxy
    def remove_proxy(self):
        if self.module.check_mode:
            self.changed = True
            return
        command = 'rmproxy'
        command_options = None
        cmdargs = None
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.log('Proxy removed successfully.')

    # function for creating a proxy
    def create_proxy(self):
        if self.module.check_mode:
            self.changed = True
            return
        command = 'mkproxy'
        command_options = {}
        if self.proxy_type == 'open_proxy':
            if self.proxy_url:
                command_options['url'] = self.proxy_url
            if self.proxy_port:
                command_options['port'] = self.proxy_port
        elif self.proxy_type == 'basic_authentication':
            if self.proxy_url:
                command_options['url'] = self.proxy_url
            if self.proxy_port:
                command_options['port'] = self.proxy_port
            if self.proxy_username:
                command_options['username'] = self.proxy_username
            if self.proxy_password:
                command_options['password'] = self.proxy_password
        elif self.proxy_type == 'certificate':
            if self.proxy_url:
                command_options['url'] = self.proxy_url
            if self.proxy_port:
                command_options['port'] = self.proxy_port
            if self.sslcert:
                command_options['sslcert'] = self.sslcert

        cmdargs = None
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.log("Proxy created successfully.")

    # function for probing existing proxy data
    def probe_proxy(self, data):
        modify = {}
        if self.proxy_type == 'open_proxy':
            if self.proxy_url:
                if self.proxy_url != data['url']:
                    modify['url'] = self.proxy_url
            if self.proxy_port:
                if int(self.proxy_port) != int(data['port']):
                    modify['port'] = self.proxy_port
        elif self.proxy_type == 'basic_authentication':
            if self.proxy_url:
                if self.proxy_url != data['url']:
                    modify['url'] = self.proxy_url
            if self.proxy_port:
                if self.proxy_port != int(data['port']):
                    modify['port'] = self.proxy_port
            if self.proxy_username:
                if self.proxy_username != data['username']:
                    modify['username'] = self.proxy_username
            if self.proxy_password:
                modify['password'] = self.proxy_password
        elif self.proxy_type == 'certificate':
            if self.proxy_url:
                if self.proxy_url != data['url']:
                    modify['url'] = self.proxy_url
            if self.proxy_port:
                if self.proxy_port != int(data['port']):
                    modify['port'] = self.proxy_port
            if self.sslcert:
                modify['sslcert'] = self.sslcert
        return modify

    # function for updating a proxy
    def update_proxy(self, data):
        if self.module.check_mode:
            self.changed = True
            return
        command = 'chproxy'
        command_options = data
        cmdargs = None
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.log('Proxy updated successfully.')

    # function for fetching existing cloud callhome data
    def get_existing_cloud_callhome_data(self):
        data = {}
        command = 'lscloudcallhome'
        command_options = None
        cmdargs = None
        data = self.restapi.svc_obj_info(command, command_options, cmdargs)
        return data

    # function for enabling cloud callhome
    def enable_cloud_callhome(self):
        if self.module.check_mode:
            self.changed = True
            return
        command = 'chcloudcallhome'
        command_options = {
            'enable': True
        }
        cmdargs = None
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.changed = True
        self.log('Cloud callhome enabled.')

    # function for doing connection test for cloud callhome
    def test_connection_cloud_callhome(self):
        if self.module.check_mode:
            self.changed = True
            return
        command = 'sendcloudcallhome'
        command_options = {
            'connectiontest': True
        }
        self.restapi.svc_run_command(command, command_options, None)
        self.changed = True
        self.log('Cloud callhome connection tested.')
        # the connection testing can take some time to complete.
        time.sleep(3)

    # function for managing proxy server
    def manage_proxy_server(self):
        proxy_data = self.get_existing_proxy()
        if proxy_data['enabled'] == 'no':
            if self.proxy_type == 'no_proxy':
                self.log('Proxy already disabled.')
            else:
                self.create_proxy()
                self.changed = True
        elif proxy_data['enabled'] == 'yes':
            if self.proxy_type == 'no_proxy':
                self.remove_proxy()
                self.changed = True
            else:
                modify = self.probe_proxy(proxy_data)
                if modify:
                    self.update_proxy(modify)
                    self.changed = True

    # function for disabling cloud callhome
    def disable_cloud_callhome(self):
        if self.module.check_mode:
            self.changed = True
            return
        command = 'chcloudcallhome'
        command_options = {
            'disable': True
        }
        cmdargs = None
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.log('Cloud callhome disabled.')

    # function to initiate callhome with cloud
    def initiate_cloud_callhome(self):
        msg = ''
        attempts = 0
        limit_reached = False
        active_status = False
        # manage proxy server
        self.manage_proxy_server()
        # update email data
        self.update_email_data()
        # manage cloud callhome
        lsdata = self.get_existing_cloud_callhome_data()
        if lsdata['status'] == 'enabled':
            # perform connection test
            self.test_connection_cloud_callhome()
        else:
            self.enable_cloud_callhome()
            # cloud callhome takes some time to get enabled.
            while not active_status:
                attempts += 1
                if attempts > 10:
                    limit_reached = True
                    break
                lsdata = self.get_existing_cloud_callhome_data()
                if lsdata['status'] == 'enabled':
                    active_status = True
                time.sleep(2)
            if limit_reached:
                # the module will exit without performing connection test.
                msg = "Callhome with Cloud is enabled. Please check connection to proxy."
                self.changed = True
                return msg
            if active_status:
                # perform connection test
                self.test_connection_cloud_callhome()
        msg = "Callhome with Cloud enabled successfully."
        self.changed = True
        return msg

    # function to initiate callhome with email notifications
    def initiate_email_callhome(self):
        msg = ''
        # manage email server
        email_server_exists = self.check_email_server_exists()
        if email_server_exists:
            self.log("Email server already exists.")
        else:
            self.create_email_server()
            self.changed = True
        # manage support email user
        self.manage_support_email_user()
        # manage local email user
        email_user_exists = self.check_email_user_exists()
        if email_user_exists:
            email_user_modify = {}
            if email_user_exists['inventory'] != self.inventory:
                email_user_modify['inventory'] = self.inventory
            if email_user_modify:
                self.update_email_user(email_user_modify, email_user_exists['id'])
        else:
            self.create_email_user()
        # manage email data
        self.update_email_data()
        # enable email callhome
        self.enable_email_callhome()
        msg = "Callhome with email enabled successfully."
        self.changed = True
        return msg

    def apply(self):
        self.changed = False
        msg = None
        self.basic_checks()
        if self.state == 'enabled':
            # enable cloud callhome
            if self.callhome_type == 'cloud services':
                msg = self.initiate_cloud_callhome()
            # enable email callhome
            elif self.callhome_type == 'email':
                msg = self.initiate_email_callhome()
            # enable both cloud and email callhome
            elif self.callhome_type == 'both':
                temp_msg = ''
                temp_msg += self.initiate_cloud_callhome()
                temp_msg += ' ' + self.initiate_email_callhome()
                if temp_msg:
                    msg = temp_msg
            # manage chsystem parameters
            system_data = self.get_system_data()
            system_modify = self.probe_system(system_data)
            if system_modify:
                self.update_system(system_modify)
        elif self.state == 'disabled':
            if self.callhome_type == 'cloud services':
                cloud_callhome_data = self.get_existing_cloud_callhome_data()
                if cloud_callhome_data['status'] == 'disabled':
                    msg = "Callhome with cloud already disabled."
                elif cloud_callhome_data['status'] == 'enabled':
                    self.disable_cloud_callhome()
                    msg = "Callhome with cloud disabled successfully."
                    self.changed = True
            elif self.callhome_type == 'email':
                self.disable_email_callhome()
                msg = "Callhome with email disabled successfully."
                self.changed = True
            elif self.callhome_type == 'both':
                # disable email callhome
                self.disable_email_callhome()
                msg = "Callhome with email disabled successfully."
                self.changed = True
                # disable cloud callhome
                cloud_callhome_data = self.get_existing_cloud_callhome_data()
                if cloud_callhome_data['status'] == 'disabled':
                    msg += " Callhome with cloud already disabled."
                elif cloud_callhome_data['status'] == 'enabled':
                    self.disable_cloud_callhome()
                    msg += " Callhome with cloud disabled successfully."
                    self.changed = True
        self.module.exit_json(msg=msg, changed=self.changed)


def main():
    v = IBMSVCCallhome()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
