#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 IBM CORPORATION
# Author(s): Sreshtant Bohidar <sreshtant.bohidar@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_manage_user
short_description: This module manages user on IBM Storage Virtualize family systems
description:
  - Ansible interface to manage 'mkuser', 'rmuser', and 'chuser' commands.
version_added: "1.7.0"
options:
    name:
        description:
            - Specifies the unique username.
        required: true
        type: str
    state:
        description:
            - Creates or updates (C(present)) or removes (C(absent)) a user.
        choices: [ present, absent ]
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
    user_password:
        description:
            - Specifies the password associated with the user.
            - Applies when I(state=present).
        type: str
    nopassword:
        description:
            - Specifies that the user's password is to be deleted.
            - Applies when I(state=present), to modify a user.
        type: bool
    keyfile:
        description:
            - Specifies the name of the file containing the Secure Shell (SSH) public key.
            - Applies when I(state=present).
        type: str
    nokey:
        description:
            - Specifies that the user's SSH key is to be deleted.
            - Applies when I(state=present), to modify a user.
        type: bool
    auth_type:
        description:
            - Specifies whether the user authenticates to the system using a remote authentication service or system authentication methods.
            - Only supported value is 'usergrp'.
            - Required when I(state=present), to create a user.
        choices: [ usergrp ]
        type: str
    usergroup:
        description:
            - Specifies the name of the user group with which the local user is to be associated.
            - Applies when I(state=present) and I(auth_type=usergrp).
        type: str
    forcepasswordchange:
        description:
            - Specifies that the password is to be changed on next login.
            - Applies when I(state=present), to modify a user.
        type: bool
    lock:
        description:
            - Specifies to lock the account indefinitely. The user cannot log in unless unlocked again with the parameter I(unlock).
            - Applies when I(state=present), to modify a user.
            - Parameters I(lock) and I(unlock) are mutually exclusive.
        type: bool
    unlock:
        description:
            - Specifies to unlock the account so it can be logged in to again.
            - Applies when I(state=present), to modify a user.
            - Parameters I(lock) and I(unlock) are mutually exclusive.
        type: bool
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
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create a user
  ibm.storage_virtualize.ibm_svc_manage_user:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    state: present
    name: user-name
    user_password: user-password
    auth_type: usergrp
    usergroup: usergroup-name
- name: Remove a user
  ibm.storage_virtualize.ibm_svc_manage_user:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    state: absent
    name: user-name
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCUser(object):
    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(type='str', required=True, choices=['present', 'absent']),
                auth_type=dict(type='str', required=False, choices=['usergrp']),
                user_password=dict(type='str', required=False, no_log=True),
                nopassword=dict(type='bool', required=False),
                keyfile=dict(type='str', required=False, no_log=True),
                nokey=dict(type='bool', required=False),
                forcepasswordchange=dict(type='bool', required=False),
                lock=dict(type='bool', required=False),
                unlock=dict(type='bool', required=False),
                usergroup=dict(type='str', required=False),
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required
        self.name = self.module.params['name']
        self.state = self.module.params['state']

        # Required during creation of user
        self.auth_type = self.module.params['auth_type']
        self.usergroup = self.module.params['usergroup']

        # Optional
        self.user_password = self.module.params.get('user_password', False)
        self.nopassword = self.module.params.get('nopassword', False)
        self.keyfile = self.module.params.get('keyfile', False)
        self.nokey = self.module.params.get('nokey', False)
        self.forcepasswordchange = self.module.params.get('forcepasswordchange', False)
        self.lock = self.module.params.get('lock', False)
        self.unlock = self.module.params.get('unlock', False)

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

    # perform some basic checks
    def basic_checks(self):
        # Handling for mandatory parameter name
        if not self.name:
            self.module.fail_json(msg="Missing mandatory parameter: name")
        # Handling for mandatory parameter state
        if not self.state:
            self.module.fail_json(msg="Missing mandatory parameter: state")
        # Handling mutually exclusive cases amoung parameters
        if self.user_password and self.nopassword:
            self.module.fail_json(msg="Mutually exclusive parameter: user_password, nopassword")
        if self.lock and self.unlock:
            self.module.fail_json(msg="Mutually exclusive parameter: lock, unlock")
        if self.keyfile and self.nokey:
            self.module.fail_json(msg="Mutually exclusive parameter: keyfile, nokey")
        if self.auth_type == 'usergrp' and not self.usergroup:
            self.module.fail_json(msg="Parameter [usergroup] is required when auth_type is usergrp")

    # function to get user data
    def get_existing_user(self):
        merged_result = {}
        data = self.restapi.svc_obj_info(cmd='lsuser', cmdopts=None, cmdargs=[self.name])
        self.log('GET: user data: %s', data)
        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        return merged_result

    # function for creating new user
    def create_user(self):
        # Handling unsupported parameter during user creation
        if self.nokey or self.nopassword or self.lock or self.unlock or self.forcepasswordchange:
            self.module.fail_json(msg="Parameters [nokey, nopassword, lock, unlock, forcepasswordchange] not applicable while creating a user")
        # Handling for mandatory parameter role
        if not self.auth_type:
            self.module.fail_json(msg="Missing required parameter: auth_type")
        if self.auth_type == 'usergrp' and not self.usergroup:
            self.module.fail_json(msg="Missing required parameter: usergroup")
        if self.module.check_mode:
            self.changed = True
            return
        command = 'mkuser'
        command_options = {
            'name': self.name,
        }
        if self.user_password:
            command_options['password'] = self.user_password
        if self.keyfile:
            command_options['keyfile'] = self.keyfile
        if self.usergroup:
            command_options['usergrp'] = self.usergroup
        if self.forcepasswordchange:
            command_options['forcepasswordchange'] = self.forcepasswordchange

        result = self.restapi.svc_run_command(command, command_options, cmdargs=None)
        self.log("create user result %s", result)
        if 'message' in result:
            self.changed = True
            self.log("create user result message %s", result['message'])
        else:
            self.module.fail_json(
                msg="Failed to create user [%s]" % self.name)

    # function for probing an existing user
    def probe_user(self, data):
        properties = {}

        if self.usergroup:
            if self.usergroup != data['usergrp_name']:
                properties['usergrp'] = self.usergroup
        if self.user_password:
            properties['password'] = self.user_password
        if self.nopassword:
            if data['password'] == 'yes':
                properties['nopassword'] = True
        if self.keyfile:
            properties['keyfile'] = self.keyfile
        if self.nokey:
            if data['ssh_key'] == "yes":
                properties['nokey'] = True
        if self.lock:
            properties['lock'] = True
        if self.unlock:
            properties['unlock'] = True
        if self.forcepasswordchange:
            properties['forcepasswordchange'] = True

        return properties

    # function for updating an existing user
    def update_user(self, data):
        if self.module.check_mode:
            self.changed = True
            return
        self.log("updating user '%s'", self.name)
        command = 'chuser'
        for parameter in data:
            command_options = {
                parameter: data[parameter]
            }
            self.restapi.svc_run_command(command, command_options, [self.name])
        self.changed = True

    # function for removing an existing user
    def remove_user(self):
        # Handling unsupported parameter during user removal
        if self.nokey or self.nopassword or self.lock or self.unlock or self.forcepasswordchange:
            self.module.fail_json(msg="Parameters [nokey, nopassword, lock, unlock, forcepasswordchange] not applicable while removing a user")
        if self.module.check_mode:
            self.changed = True
            return
        self.log("deleting user '%s'", self.name)
        command = 'rmuser'
        command_options = None
        cmdargs = [self.name]
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.changed = True

    def apply(self):
        changed = False
        msg = None
        modify = {}
        self.basic_checks()

        user_data = self.get_existing_user()

        if user_data:
            if self.state == 'absent':
                self.log("CHANGED: user exists, but requested state is 'absent'")
                changed = True
            elif self.state == 'present':
                # initiate probing of an existing user
                modify = self.probe_user(user_data)
                if modify:
                    self.log("CHANGED: user exists, but probe detected changes")
                    changed = True
        else:
            if self.state == 'present':
                self.log("CHANGED: user does not exist, but requested state is 'present'")
                changed = True
        if changed:
            if self.state == 'present':
                if not user_data:
                    # initiate creation of new user
                    self.create_user()
                    msg = "User [%s] has been created." % self.name
                else:
                    # initiate updation os an existing user
                    self.update_user(modify)
                    msg = "User [%s] has been modified." % self.name
            elif self.state == 'absent':
                # initiate deletion of an existing user
                self.remove_user()
                msg = "User [%s] has been removed." % self.name
            if self.module.check_mode:
                msg = "Skipping changes due to check mode."
        else:
            if self.state == 'absent':
                msg = "User [%s] does not exist." % self.name
            elif self.state == 'present':
                msg = "User [%s] already exist (no modificationes detected)." % self.name

        self.module.exit_json(msg=msg, changed=changed)


def main():
    v = IBMSVCUser()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
