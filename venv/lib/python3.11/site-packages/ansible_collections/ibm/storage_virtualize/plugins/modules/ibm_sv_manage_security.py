#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2023 IBM CORPORATION
# Author(s): Sumit Kumar Gupta <sumit.gupta16@ibm.com>
#            Sandip Gulab Rajbanshi <sandip.rajbanshi@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ibm_sv_manage_security
short_description: This module manages security options on IBM Storage Virtualize family storage systems
description:
    - Ansible interface to manage 'chsecurity' command.
version_added: "2.1.0"
options:
    clustername:
        description:
            - The hostname or management IP of the Storage Virtualize storage system.
        required: true
        type: str
    domain:
        description:
            - Domain for the Storage Virtualize storage system.
            - Valid when hostname is used for the parameter I(clustername).
        type: str
    username:
        description:
            - REST API username for the Storage Virtualize storage system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    password:
        description:
            - REST API password for the Storage Virtualize storage system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    token:
        description:
            - The authentication token to verify a user on the Storage Virtualize storage system.
            - To generate a token, use the ibm_svc_auth module.
        type: str
    sshprotocol:
        description:
            - Specifies the numeric value for the SSH security level setting in range 1 - 4.
            - The level 1 Allows the following key exchange methods
              curve25519-sha256
              curve25519-sha256@libssh.org
              ecdh-sha2-nistp256
              ecdh-sha2-nistp384
              ecdh-sha2-nistp521
              diffie-hellman-group-exchange-sha256
              diffie-hellman-group16-sha512
              diffie-hellman-group18-sha512
              diffie-hellman-group14-sha256
              diffie-hellman-group14-sha1
              diffie-hellman-group1-sha1
              diffie-hellman-group-exchange-sha1
            - The level 2 Allows the following key exchange methods
              curve25519-sha256
              curve25519-sha256@libssh.org
              ecdh-sha2-nistp256
              ecdh-sha2-nistp384
              ecdh-sha2-nistp521
              diffie-hellman-group-exchange-sha256
              diffie-hellman-group16-sha512
              diffie-hellman-group18-sha512
              diffie-hellman-group14-sha256
              diffie-hellman-group14-sha1
            - The level 3 Allows the following key exchange methods
              curve25519-sha256
              curve25519-sha256@libssh.org
              ecdh-sha2-nistp256
              ecdh-sha2-nistp384
              ecdh-sha2-nistp521
              diffie-hellman-group-exchange-sha256
              diffie-hellman-group16-sha512
              diffie-hellman-group18-sha512
              diffie-hellman-group14-sha256
            - The level 4 Allows the following key exchange methods
              curve25519-sha256
              curve25519-sha256@libssh.org
              ecdh-sha2-nistp256
              ecdh-sha2-nistp384
              ecdh-sha2-nistp521
        type: int
    guitimeout:
        description:
            - Specifies the amount of time (in minutes) in range 5 - 240 before a session expires and the user is logged
              out of the GUI for inactivity.
        type: int
    clitimeout:
        description:
            - Specifies the amount of time (in minutes) in range 5 - 240 before a session expires and the user is logged
              out of the CLI for inactivity.
        type: int
    minpasswordlength:
        description:
            - Specifies the minimum length requirement in range 6 -64 for user account passwords on the system.
        type: int
    passwordspecialchars:
        description:
            - Specifies number of minimum required special characters in range 0 - 3 in passwords for local users.
        type: int
    passworduppercase:
        description:
            - Specifies number of minimum uppercase characters in range 0 - 3 in passwords for local users.
        type: int
    passwordlowercase:
        description:
            - Specifies number of minimum lowercase characters in range 0 - 3 required in passwords for local users.
        type: int
    passworddigits:
        description:
            - Specifies mimimum number of digits in range 0 -3 required in passwords for local users.
        type: int
    checkpasswordhistory:
        description:
            - Specifies whether the system prevents the user from reusing a previous password.
        choices: ['yes', 'no']
        type: str
    maxpasswordhistory:
        description:
            - Specifies the number of previous passwords in range 0 - 10 to compare with if checkpasswordhistory is
              enabled. A value of 0 means that the new password is compared with the current password only.
        type: int
    minpasswordage:
        description:
            - Specifies the minimum number of days between password changes in range 0 -365. This setting is enforced if
              checkpasswordhistory is enabled. This restriction is ignored if the password is expired. The setting does
              nothing if the value is greater than the passwordexpiry value.
        type: int
    passwordexpiry:
        description:
            - Specifies the number of days in range 0 - 365 before a password expires. A value of 0 means the feature is
              disabled and passwords do not expire.
        type: int
    expirywarning:
        description:
            - Specifies the number of days in range 0 -30 before a password expires to raise a warning. The warning is
              displayed on every CLI login until the password is changed. A value of 0 means that the feature is
              disabled and warnings are not displayed.
        type: int
    superuserlocking:
        description:
            - Specifies whether the locking policy configured on the system also applies to the superuser. The value is
              either enable or disable. This parameter is only supported on systems with a dedicated technician port.
        choices: ['enable', 'disable']
        type: str
    maxfailedlogins:
        description:
            - Specifies the number of failed login attempts in range 0 -10 before the user account is locked for the
              amount of time that is specified in lockout period. A value of 0 means that the feature is disabled and
              accounts are not locked out after failed login attempts.
        type: int
    lockoutperiod:
        description:
            - Specifies the number of minutes in range 0 - 10080 that a user is locked out for if the max failed logins
              value is reached. A value of 0 implies the user is indefinitely locked out when the max failed login
              attempts are reached.
        type: int
    restapitimeout:
        description:
            - Specifies token expiry time in minutes in the range 10 - 120.
        type: int
    superusermultifactor:
        description:
            - Specifies whether the superuser should be prompted for multifactor authentication.
        choices: ['yes', 'no']
        type: str
    sshmaxtries:
        description:
            - Specifies the amount of allowed login attempts (in range 1-10) per a single SSH connection.
        type: int
    sshgracetime:
        description:
            - Specifies the duration of time in seconds in range 15-1800, a user has to enter login factors per SSH
              connection before the connection is
              terminated.
        type: int
    superuserpasswordkeyrequired:
        description:
            - Specifies whether the superuser must provide both a password and SSH key for authentication.
        type: str
        choices: ['yes', 'no']
    disablesuperusergui:
        description:
            - Specifies whether GUI access must be disabled for the superuser.
        choices: ['yes', 'no']
        type: str
    disablesuperuserrest:
        description:
            - Specifies whether REST API access must be disabled for the superuser.
        choices: ['yes', 'no']
        type: str
    disablesuperusercim:
        description:
            - Specifies whether CIMOM access must be disabled for the superuser.
        choices: ['yes', 'no']
        type: str
    resetsshprotocol:
        description:
            - Resets the SSH protocol security level to the default value 3 and configures the system to automatically
              follow the suggested level.
        type: bool
    patchautoupdate:
        description:
            - Enables or disables the patch auto updater service.
        choices: ['yes', 'no']
        type: str
    log_path:
        description:
            - Path of debug log file.
        type: str
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool

author:
    - Sumit Kumar Gupta (@sumitguptaibm)
    - Lavanya C R (@lavanyacr)
    - Sandip Gulab Rajbanshi (@Sandip-Rajbanshi)
notes:
    - This module supports C(check_mode).
    - The 3-site-orchestrator does not support SSH protocol level 4.
'''

EXAMPLES = r'''
- name: Change max failed login limit
  ibm.storage_virtualize.ibm_sv_manage_security:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   log_path: /tmp/playbook.debug
   maxfailedlogins: 5

- name: Change SSH protocol level
  ibm.storage_virtualize.ibm_sv_manage_security:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   log_path: /tmp/playbook.debug
   sshprotocol: 2

- name: Enables the patch auto updater service
  ibm.storage_virtualize.ibm_sv_manage_security:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   log_path: /tmp/playbook.debug
   patchautoupdate: 'yes'
'''

RETURN = r'''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (IBMSVCRestApi,
                                                                                           svc_argument_spec,
                                                                                           get_logger)
from ansible.module_utils._text import to_native


class IBMSVSecurityMgmt(object):
    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                sshprotocol=dict(type='int'),
                guitimeout=dict(type='int'),
                clitimeout=dict(type='int'),
                minpasswordlength=dict(type='int', no_log=False),
                passwordspecialchars=dict(type='int', no_log=False),
                passworduppercase=dict(type='int', no_log=False),
                passwordlowercase=dict(type='int', no_log=False),
                passworddigits=dict(type='int', no_log=False),
                checkpasswordhistory=dict(type='str', choices=['yes', 'no'], no_log=False),
                maxpasswordhistory=dict(type='int', no_log=False),
                minpasswordage=dict(type='int', no_log=False),
                passwordexpiry=dict(type='int', no_log=False),
                expirywarning=dict(type='int'),
                superuserlocking=dict(type='str', choices=['enable', 'disable']),
                maxfailedlogins=dict(type='int'),
                lockoutperiod=dict(type='int'),
                restapitimeout=dict(type='int'),
                superusermultifactor=dict(type='str', choices=['yes', 'no']),
                sshmaxtries=dict(type='int'),
                sshgracetime=dict(type='int'),
                superuserpasswordkeyrequired=dict(type='str', choices=['yes', 'no']),
                disablesuperusergui=dict(type='str', choices=['yes', 'no']),
                disablesuperuserrest=dict(type='str', choices=['yes', 'no']),
                disablesuperusercim=dict(type='str', choices=['yes', 'no']),
                resetsshprotocol=dict(type='bool'),
                patchautoupdate=dict(type='str', choices=['yes', 'no'])
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

        for param, value in self.module.params.items():
            setattr(self, param, value)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Initialize changed variable
        self.changed = False

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

    def change_security_settings(self):
        cmd = 'chsecurity'
        cmd_opts = {}

        for attr, value in vars(self).items():
            if attr in ['restapi', 'log', 'module', 'clustername', 'domain', 'username', 'password', 'validate_certs',
                        'token', 'log_path']:
                continue
            cmd_opts[attr] = value

        result = self.restapi.svc_run_command(cmd, cmd_opts, cmdargs=None)
        if result == "":
            self.changed = True
            self.log("chsecurity successful !!")
        else:
            self.module.fail_json(msg="chsecurity failed !!")

    def apply(self):
        msg = None
        if self.module.check_mode:
            self.changed = True
        else:
            self.change_security_settings()
        self.module.exit_json(msg=msg, changed=self.changed)


def main():
    v = IBMSVSecurityMgmt()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
