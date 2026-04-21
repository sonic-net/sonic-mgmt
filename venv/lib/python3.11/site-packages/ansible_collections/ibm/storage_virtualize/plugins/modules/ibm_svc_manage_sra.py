#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 IBM CORPORATION
# Author(s): Sanjaikumaar M <sanjaikumaar.m@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_manage_sra
short_description: This module manages remote support assistance configuration on IBM Storage Virtualize family systems
version_added: "1.7.0"
description:
  - Ansible interface to manage 'chsra' support remote assistance command.
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
            - Enables (C(enabled)) or disables (C(disabled)) the remote support assistance.
        choices: [ enabled, disabled ]
        required: true
        type: str
    support:
        description:
            - Specifies the support assistance through C(remote) or C(onsite).
        choices: [ remote, onsite ]
        type: str
        required: true
    name:
        description:
            - Specifies the list of unique names for the support center or proxy to be defined.
            - Required when I(support=remote), to enable remote support assistance.
        type: list
        elements: str
    sra_ip:
        description:
            - Specifies the list of IP addresses or fully qualified domain names for the new support center or proxy server.
            - Required when I(support=remote) and I(state=enabled), to enable support remote assistannce.
        type: list
        elements: str
    sra_port:
        description:
            - Specifies the list of port numbers for the new support center or proxy server.
            - Required when I(support=remote) and I(state=enabled), to enable support remote assistannce.
        type: list
        elements: str
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
author:
    - Sanjaikumaar M (@sanjaikumaar)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Enable support remote assistance
  ibm.storage_virtualize.ibm_svc_manage_sra:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: "{{ log_path }}"
    support: remote
    state: enabled
    name:
      - proxy_1
      - proxy_2
      - proxy_3
    sra_ip:
      - '0.0.0.0'
      - '1.1.1.1'
      - '2.1.2.2'
    sra_port:
      - 8888
      - 9999
      - 8800
- name: Disable support remote assistance
  ibm.storage_virtualize.ibm_svc_manage_sra:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: "{{ log_path }}"
    support: remote
    state: disabled
    name:
      - proxy_1
      - proxy_2
      - proxy_3
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (
    IBMSVCRestApi, svc_argument_spec,
    get_logger
)
from ansible.module_utils._text import to_native


class IBMSVCSupportRemoteAssistance:

    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                state=dict(
                    type='str',
                    required=True,
                    choices=['enabled', 'disabled']
                ),
                support=dict(
                    type='str',
                    required=True,
                    choices=['remote', 'onsite']
                ),
                name=dict(type='list', elements='str'),
                sra_ip=dict(type='list', elements='str'),
                sra_port=dict(type='list', elements='str')
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # Required parameters
        self.support = self.module.params['support']
        self.state = self.module.params['state']

        # Optional parameters
        self.name = self.module.params.get('name', [])
        self.sra_ip = self.module.params.get('sra_ip', [])
        self.sra_port = self.module.params.get('sra_port', [])

        self.basic_checks()

        # Varialbe to store some frequently used data
        self.sra_status_detail = None

        # logging setup
        self.log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, self.log_path)
        self.log = log.info
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
        self.filtered_params = dict(
            filter(
                lambda item: item[0] in ['name', 'sra_ip', 'sra_port'],
                self.module.params.items()
            )
        )
        if self.support == 'remote' and self.state == 'enabled':
            if self.name and self.sra_ip and self.sra_port:
                if len(self.name) == len(self.sra_ip) == len(self.sra_port):
                    if not all([all(self.name), all(self.sra_ip), all(self.sra_port)]):
                        missing_params = ', '.join([k for k, v in self.filtered_params.items() if not all(v)])
                        self.module.fail_json(
                            msg='{0} should not contain blank values'.format(missing_params)
                        )
                else:
                    self.module.fail_json(
                        msg='Name, sra_ip and sra_port parameters should contain same number of arguments'
                    )
            else:
                missing_params = ', '.join([k for k, v in self.filtered_params.items() if not v])
                self.module.fail_json(
                    msg='support is remote and state is enabled but following parameter missing: {0}'.format(missing_params)
                )
        elif self.support == 'remote' and self.state == 'disabled':
            if self.sra_ip or self.sra_port:
                invalid_params = ', '.join([k for k, v in self.filtered_params.items() if k in ['sra_ip', 'sra_port'] and v])
                self.module.fail_json(
                    msg='{0} should not be passed when support=remote and state=disabled'.format(invalid_params)
                )
        elif self.support == 'onsite':
            if self.name or self.sra_ip or self.sra_port:
                invalid_params = ', '.join([k for k, v in self.filtered_params.items()])
                self.module.fail_json(
                    msg='{0} should not be passed when support=onsite'.format(invalid_params)
                )

    def is_sra_enabled(self):
        if self.sra_status_detail:
            return self.sra_status_detail['status'] == 'enabled'

        result = self.restapi.svc_obj_info(
            cmd='lssra',
            cmdopts=None,
            cmdargs=None
        )
        self.sra_status_detail = result
        return result['status'] == 'enabled'

    def is_remote_support_enabled(self):
        if self.sra_status_detail:
            return self.sra_status_detail['remote_support_enabled'] == 'yes'

        result = self.restapi.svc_obj_info(
            cmd='lssra',
            cmdopts=None,
            cmdargs=None
        )
        return result['remote_support_enabled'] == 'yes'

    def is_proxy_exist(self, obj_name):
        obj = {}
        result = self.restapi.svc_obj_info(
            cmd='lssystemsupportcenter',
            cmdopts=None,
            cmdargs=[obj_name]
        )

        if isinstance(result, list):
            for d in result:
                obj.update(d)
        else:
            obj = result

        return obj

    def sra_probe(self):
        if self.module.check_mode:
            self.changed = True
            return

        message = ''
        if (self.support == 'remote' and not self.is_remote_support_enabled()) \
                or (self.support == 'onsite' and self.is_remote_support_enabled()):

            message += 'SRA configuration cannot be updated right now. '

        if any(self.add_proxy_details()):
            message += 'Proxy server details cannot be updated when SRA is enabled. '

        message += 'Please disable SRA and try to update.' if message else ''

        self.msg = message if message else self.msg

        return self.msg

    def add_proxy_details(self):
        existed = []
        if self.support == 'remote':
            cmd = 'mksystemsupportcenter'
            cmdargs = []

            for nm, ip, port in zip(self.name, self.sra_ip, self.sra_port):
                if nm != 'None' and ip != 'None' and port != 'None':
                    if not self.is_proxy_exist(nm):
                        existed.append(True)
                        if not self.is_sra_enabled():
                            cmdopts = {
                                'name': nm,
                                'ip': ip,
                                'port': port,
                                'proxy': 'yes'
                            }
                            self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
                            self.log('Proxy server(%s) details added', nm)
                    else:
                        self.log('Skipping, Proxy server(%s) already exist', nm)
                else:
                    missing_params = ', '.join([k for k, v in self.filtered_params.items() if 'None' in v])
                    self.module.fail_json(
                        msg='support is remote and state is enabled but following parameter missing: {0}'.format(missing_params)
                    )

        return existed

    def remove_proxy_details(self):
        if self.support == 'remote':
            cmd = 'rmsystemsupportcenter'
            cmdopts = {}

            for nm in self.name:
                if nm and nm != 'None':
                    if self.is_proxy_exist(nm):
                        cmdargs = [nm]
                        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
                        self.log('Proxy server(%s) details removed', nm)
                    else:
                        self.log('Proxy server(%s) does not exist', nm)
                else:
                    self.module.fail_json(
                        msg='support is remote and state is disabled but following parameter is blank: name'
                    )

    def enable_sra(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.add_proxy_details()

        cmd = 'chsra'
        cmdopts = {}
        cmdargs = ['-enable']

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        if self.support == 'remote':
            cmdargs = ['-remotesupport', 'enable']
            self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        self.log('%s support assistance enabled', self.support.capitalize())

        self.changed = True

    def disable_sra(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'chsra'
        cmdopts = {}

        if self.support == 'remote':
            cmdargs = ['-remotesupport', 'disable']
            self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        cmdargs = ['-disable']
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
        self.log('%s support assistance disabled', self.support.capitalize())

        self.remove_proxy_details()
        self.changed = True

    def apply(self):
        if self.is_sra_enabled():
            if self.state == 'enabled':
                if not self.sra_probe():
                    self.msg = 'Support remote assistance already enabled. '\
                               'No modifications done.'
            else:
                self.disable_sra()
                self.msg = 'Support remote assistance disabled.'
        else:
            if self.state == 'disabled':
                self.msg = 'Support remote assistance is already disabled.'
            else:
                self.enable_sra()
                self.msg = 'Support remote assistance({0}) enabled.'.format(
                    self.support
                )

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'

        self.module.exit_json(msg=self.msg, changed=self.changed)


def main():
    v = IBMSVCSupportRemoteAssistance()
    try:
        v.apply()
    except Exception as e:
        v.log('Exception in apply(): \n%s', format_exc())
        v.module.fail_json(msg='Module failed. Error [%s].' % to_native(e))


if __name__ == '__main__':
    main()
