#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2023 IBM CORPORATION
# Author(s): Shilpi Jain <shilpi.jain1@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_sv_manage_syslog_server
short_description: This module manages syslog server on IBM Storage Virtualize family systems
version_added: '2.1.0'
description:
  - This Ansible module provides the interface to manage syslog servers through 'mksyslogserver',
    'chsyslogserver' and 'rmsyslogserver' Storage Virtualize commands.
options:
    clustername:
        description:
            - The hostname or management IP of the Storage Virtualize system.
        required: true
        type: str
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
            - To generate a token, use the M(ibm.storage_virtualize.ibm_svc_auth) module.
        type: str
    log_path:
        description:
            - Path of debug log file.
        type: str
    state:
        description:
            - Creates, updates (C(present)) or deletes (C(absent)) a syslog server.
        choices: [ present, absent ]
        required: true
        type: str
    name:
        description:
            - Specifies the name of a syslog server.
        type: str
        required: true
    old_name:
        description:
            - Specifies the old name of a syslog server to rename.
            - Valid when I(state=present), to rename the existing syslog server.
        type: str
    ip:
        description:
            - Specifies the Internet Protocol (IP) address or domain name of the syslog server.
              If a domain name is specified, a DNS server must be configured on the system.
        type: str
    facility:
        description:
            - Specifies the facility number used in syslog messages.
              This number identifies the origin of the message to the receiving server. The default value is 0.
              The parameters I(facility) and I (cadf) are mutually exclusive.
        type: int
    error:
        description:
            - Specifies whether the server receives error notifications.
              If specified as on, error notifications are sent to the syslog server. The default value is on.
        type: str
        choices: [ 'off', 'on' ]
    warning:
        description:
            - Specifies whether the server receives warning notifications.
              If specified as on, warning notifications are sent to the syslog server. The default value is on.
        type: str
        choices: [ 'off', 'on' ]
    info:
        description:
            - Specifies whether the server receives information notifications.
              If specified as on, information notifications are sent to the syslog server. The default value is on.
        type: str
        choices: [ 'off', 'on' ]
    audit:
        description:
            - Specifies whether the server receives CLI audit logs. The default value is off.
        type: str
        choices: [ 'off', 'on' ]
    login:
        description:
            - Specifies whether the server receives authentication logs. The default value is off.
        type: str
        choices: [ 'off', 'on' ]
    protocol:
        description:
            - Specifies the communication protocol that is used by this server. The default value is udp.
        type: str
        choices: [ tcp, udp, tls ]
    port:
        description:
            - Specifies the communication port that is used by this server.
              The parameter I(protocol) must be specified while specifying this parameter.
              The default value is 514 for udp and 6514 for tcp.
        type: int
    cadf:
        description:
            - Specifies that Cloud Auditing Data Federation (CADF) data reporting be turned on or off.
              The parameters I(facility) and I (cadf) are mutually exclusive.
        type: str
        choices: [ 'off', 'on' ]
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
author:
    - Shilpi Jain (@Shilpi-J)
    - Sumit Kumar Gupta (@sumitguptaibm)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create syslog server
  ibm.storage_virtualize.ibm_sv_manage_syslog_server:
   clustername: '{{ clustername }}'
   username: '{{ username }}'
   password: '{{ password }}'
   name: server1
   ip: 1.2.3.4
   state: present
- name: Create a syslog server that communicates with TLS
  ibm.storage_virtualize.ibm_sv_manage_syslog_server:
   clustername: '{{ clustername }}'
   username: '{{ username }}'
   password: '{{ password }}'
   name: server1
   ip: 1.2.3.4
   protocol: tls
   state: present
- name: Modify the server details
  ibm.storage_virtualize.ibm_sv_manage_syslog_server:
   clustername: '{{ clustername }}'
   username: '{{ username }}'
   password: '{{ password }}'
   name: server1
   info: 'off'
   state: present
- name: Delete the syslog server
  ibm.storage_virtualize.ibm_sv_manage_syslog_server:
   clustername: '{{ clustername }}'
   username: '{{ username }}'
   password: '{{ password }}'
   name: server1
   state: absent
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (
    IBMSVCRestApi,
    svc_argument_spec,
    get_logger
)
from ansible.module_utils._text import to_native


class IBMSVSyslogserver:

    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                state=dict(
                    type='str',
                    required=True,
                    choices=['present', 'absent']
                ),
                name=dict(
                    type='str',
                    required=True
                ),
                old_name=dict(
                    type='str'
                ),
                ip=dict(
                    type='str'
                ),
                facility=dict(
                    type='int'
                ),
                error=dict(
                    type='str',
                    choices=['off', 'on']
                ),
                warning=dict(
                    type='str',
                    choices=['off', 'on']
                ),
                info=dict(
                    type='str',
                    choices=['off', 'on']
                ),
                audit=dict(
                    type='str',
                    choices=['off', 'on']
                ),
                login=dict(
                    type='str',
                    choices=['off', 'on']
                ),
                protocol=dict(
                    type='str',
                    choices=['tcp', 'udp', 'tls']
                ),
                port=dict(
                    type='int'
                ),
                cadf=dict(
                    type='str',
                    choices=['off', 'on']
                )
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # Required parameters
        self.name = self.module.params['name']
        self.state = self.module.params['state']

        # Optional parameters
        self.old_name = self.module.params.get('old_name', '')
        self.ip = self.module.params.get('ip', '')
        self.facility = self.module.params.get('facility', '')
        self.error = self.module.params.get('error', '')
        self.warning = self.module.params.get('warning', '')
        self.info = self.module.params.get('info', '')
        self.audit = self.module.params.get('audit', '')
        self.login = self.module.params.get('login', '')
        self.protocol = self.module.params.get('protocol', '')
        self.port = self.module.params.get('port', '')
        self.cadf = self.module.params.get('cadf', '')

        # logging setup
        self.log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, self.log_path)
        self.log = log.info

        self.basic_checks()

        # Dynamic variables
        self.changed = False
        self.msg = ''

        self.restapi = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.module.params['domain'],
            username=self.module.params['username'],
            password=self.module.params['password'],
            validate_certs=self.module.params['validate_certs'],
            log_path=self.log_path,
            token=self.module.params['token']
        )

    def basic_checks(self):
        if not self.name:
            self.module.fail_json(msg='Missing mandatory parameter: name')

        if self.state == 'present':
            if self.facility is not None and self.cadf is not None:
                self.module.fail_json(
                    msg='Mutually exclusive parameters: facility, cadf'
                )
            if not self.protocol and self.port:
                self.module.fail_json(
                    msg='These parameters are required together: protocol, port'
                )
            if self.old_name:
                unsupported = ('ip', 'facility', 'error', 'warning', 'info', 'login', 'audit', 'protocol', 'port', 'cadf')
                unsupported_exists = ', '.join((var for var in unsupported if getattr(self, var) not in {'', None}))

                if unsupported_exists:
                    self.module.fail_json(
                        msg='Following parameters are not supported while renaming: {0}'.format(unsupported_exists)
                    )
        elif self.state == 'absent':
            invalids = ('ip', 'facility', 'error', 'warning', 'info', 'login', 'audit', 'protocol', 'port', 'cadf', 'old_name')
            invalid_exists = ', '.join((var for var in invalids if getattr(self, var) not in {'', None}))

            if invalid_exists:
                self.module.fail_json(
                    msg='state=absent but following parameters have been passed: {0}'.format(invalid_exists)
                )

    def get_syslog_server_details(self, server_name):
        merged_result = {}

        data = self.restapi.svc_obj_info(cmd='lssyslogserver', cmdopts=None, cmdargs=[server_name])

        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        return merged_result

    def create_server(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'mksyslogserver'
        cmdopts = {
            'name': self.name
        }

        if self.ip:
            cmdopts['ip'] = self.ip
        if self.facility is not None:
            cmdopts['facility'] = self.facility
        if self.error:
            cmdopts['error'] = self.error
        if self.warning:
            cmdopts['warning'] = self.warning
        if self.info:
            cmdopts['info'] = self.info
        if self.audit:
            cmdopts['audit'] = self.audit
        if self.login:
            cmdopts['login'] = self.login
        if self.protocol:
            cmdopts['protocol'] = self.protocol
        if self.port:
            cmdopts['port'] = self.port
        if self.cadf:
            cmdopts['cadf'] = self.cadf

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log('Syslog server (%s) created', self.name)
        self.changed = True

    def server_probe(self, server_data):
        updates = []

        if self.ip and server_data['IP_address'] != self.ip:
            updates.append('ip')
        if self.facility is not None and server_data['facility'] != self.facility:
            updates.append('facility')
        if self.error and server_data['error'] != self.error:
            updates.append('error')
        if self.warning and server_data['warning'] != self.warning:
            updates.append('warning')
        if self.info and server_data['info'] != self.info:
            updates.append('info')
        if self.audit and server_data['audit'] != self.audit:
            updates.append('audit')
        if self.login and server_data['login'] != self.login:
            updates.append('login')
        if self.port is not None:
            if int(server_data['port']) != self.port:
                updates.append('port')
                updates.append('protocol')
        if self.protocol and server_data['protocol'] != self.protocol:
            updates.append('protocol')
        if self.cadf and server_data['cadf'] != self.cadf:
            updates.append('cadf')

        self.log('Syslogserver probe result: %s', updates)
        return updates

    def rename_server(self, server_data):
        msg = ''
        old_name_data = self.get_syslog_server_details(self.old_name)
        if not old_name_data and not server_data:
            self.module.fail_json(msg="Syslog server with old name {0} doesn't exist.".format(self.old_name))
        elif old_name_data and server_data:
            self.module.fail_json(msg="Syslog server [{0}] already exists.".format(self.name))
        elif not old_name_data and server_data:
            msg = "Syslog server with name [{0}] already exists.".format(self.name)
        elif old_name_data and not server_data:
            # when check_mode is enabled
            if self.module.check_mode:
                self.changed = True
                return
            self.restapi.svc_run_command('chsyslogserver', {'name': self.name}, [self.old_name])
            self.changed = True
            msg = "Syslog server [{0}] has been successfully rename to [{1}].".format(self.old_name, self.name)
        return msg

    def update_server(self, updates):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'chsyslogserver'
        cmdopts = dict((k, getattr(self, k)) for k in updates)
        cmdargs = [self.name]

        self.restapi.svc_run_command(cmd, cmdopts=cmdopts, cmdargs=cmdargs)
        self.changed = True

    def delete_server(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.restapi.svc_run_command('rmsyslogserver', None, [self.name])
        self.changed = True

    def apply(self):
        server_data = self.get_syslog_server_details(self.name)

        if self.state == 'present' and self.old_name:
            self.msg = self.rename_server(server_data)
        elif self.state == 'absent' and self.old_name:
            self.module.fail_json(msg="Rename functionality is not supported when 'state' is absent.")
        else:
            if server_data:
                if self.state == 'present':
                    modifications = self.server_probe(server_data)
                    if any(modifications):
                        self.update_server(modifications)
                        self.msg = 'Syslog server ({0}) updated.'.format(self.name)
                    else:
                        self.msg = 'Syslog server ({0}) already exists. No modifications done.'.format(self.name)
                else:
                    self.delete_server()
                    self.msg = 'Syslog server ({0}) deleted successfully.'.format(self.name)
            else:
                if self.state == 'absent':
                    self.msg = 'Syslog server ({0}) does not exist. No modifications done.'.format(self.name)
                else:
                    self.create_server()
                    self.msg = 'Syslog server ({0}) created successfully.'.format(self.name)

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'

        self.module.exit_json(
            changed=self.changed,
            msg=self.msg
        )


def main():
    v = IBMSVSyslogserver()
    try:
        v.apply()
    except Exception as e:
        v.log('Exception in apply(): \n%s', format_exc())
        v.module.fail_json(msg='Module failed. Error [%s].' % to_native(e))


if __name__ == '__main__':
    main()
