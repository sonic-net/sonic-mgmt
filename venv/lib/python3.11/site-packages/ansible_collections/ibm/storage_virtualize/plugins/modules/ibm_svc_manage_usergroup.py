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
module: ibm_svc_manage_usergroup
short_description: This module manages user group on IBM Storage Virtualize family systems
description:
  - Ansible interface to manage 'mkusergrp', 'rmusergrp', and 'chusergrp' commands.
version_added: "1.7.0"
options:
    name:
        description:
            - Specifies the name of the user group.
        required: true
        type: str
    state:
        description:
            - Creates or updates (C(present)) or removes (C(absent)) a user group.
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
    role:
        description:
            - Specifies the role associated with all users that belong to this user group.
            - Required when I(state=present).
        choices: [ Monitor, CopyOperator, Service, FlashCopyAdmin, Administrator, SecurityAdmin, VasaProvider, RestrictedAdmin, 3SiteAdmin ]
        type: str
    ownershipgroup:
        description:
            - Specifies the name of the ownership group.
            - Applies when I(state=present).
            - Parameters I(ownershipgroup) and I(noownershipgroup) are mutually exclusive.
        type: str
    noownershipgroup:
        description:
            - Specifies that the usergroup is removed from the ownership group it belonged to.
            - Applies when I(state=present), to modify a user group.
            - Parameters I(ownershipgroup) and I(noownershipgroup) are mutually exclusive.
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
- name: Create a user group
  ibm.storage_virtualize.ibm_svc_manage_usergroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    state: present
    name: user-group-name
    role: Monitor
    ownershipgroup: ownershipgroup-name
- name: Remove a user group
  ibm.storage_virtualize.ibm_svc_manage_usergroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    state: absent
    name: user-group-name
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCUsergroup(object):
    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                role=dict(type='str', required=False, choices=[
                    'Monitor', 'CopyOperator', 'Service', 'FlashCopyAdmin',
                    'Administrator', 'SecurityAdmin', 'VasaProvider',
                    'RestrictedAdmin', '3SiteAdmin'
                ]),
                ownershipgroup=dict(type='str', required=False),
                noownershipgroup=dict(type='bool', required=False),
                state=dict(type='str', required=True, choices=['present', 'absent'])
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

        # Required during creation of user group
        self.role = self.module.params['role']

        # Optional
        self.ownershipgroup = self.module.params.get('ownershipgroup', False)
        self.noownershipgroup = self.module.params.get('noownershipgroup', False)

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
        # Handing mutually exclusive cases
        if self.ownershipgroup and self.noownershipgroup:
            self.module.fail_json(msg="Mutually exclusive parameter: ownershipgroup, noownershipgroup")
        # Handling unsupported parameter while removing an usergroup
        if self.state == 'absent' and (self.role or self.ownershipgroup or self.noownershipgroup):
            self.module.fail_json(msg="Parameters [role, ownershipgroup, noownershipgroup] are not applicable while removing a usergroup")

    # function to get user group data
    def get_existing_usergroup(self):
        merged_result = {}
        data = self.restapi.svc_obj_info(cmd='lsusergrp', cmdopts=None, cmdargs=[self.name])
        self.log('GET: user group data: %s', data)
        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        return merged_result

    # function for creating new user group
    def create_user_group(self):
        # Handling unsupported parameter during usergroup creation
        if self.noownershipgroup:
            self.module.fail_json(msg="Parameter [noownershipgroup] is not applicable while creating a usergroup")
        # Handling for mandatory parameter role
        if not self.role:
            self.module.fail_json(msg="Missing mandatory parameter: role")
        if self.module.check_mode:
            self.changed = True
            return
        command = 'mkusergrp'
        command_options = {
            'name': self.name,
        }
        if self.role:
            command_options['role'] = self.role
        if self.ownershipgroup:
            command_options['ownershipgroup'] = self.ownershipgroup
        result = self.restapi.svc_run_command(command, command_options, cmdargs=None)
        self.log("create user group result %s", result)
        if 'message' in result:
            self.changed = True
            self.log("create user group result message %s", result['message'])
        else:
            self.module.fail_json(
                msg="Failed to user volume group [%s]" % self.name)

    # function for probing an existing user group
    def probe_user_group(self, data):
        properties = {}
        if self.role:
            if self.role != data['role']:
                properties['role'] = self.role
        if self.ownershipgroup:
            if self.ownershipgroup != data['owner_name']:
                properties['ownershipgroup'] = self.ownershipgroup
        if self.noownershipgroup:
            if data['owner_name']:
                properties['noownershipgroup'] = True
        return properties

    # function for updating an existing user group
    def update_user_group(self, data):
        if self.module.check_mode:
            self.changed = True
            return
        self.log("updating user group '%s'", self.name)
        command = 'chusergrp'
        command_options = {}
        if 'role' in data:
            command_options['role'] = data['role']
        if 'ownershipgroup' in data:
            command_options['ownershipgroup'] = data['ownershipgroup']
        if 'noownershipgroup' in data:
            command_options['noownershipgroup'] = True
        cmdargs = [self.name]
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.changed = True

    # function for removing an existing user group
    def remove_user_group(self):
        if self.module.check_mode:
            self.changed = True
            return
        self.log("deleting user group '%s'", self.name)
        command = 'rmusergrp'
        command_options = None
        cmdargs = [self.name]
        self.restapi.svc_run_command(command, command_options, cmdargs)
        self.changed = True

    def apply(self):
        changed = False
        msg = None
        modify = {}
        self.basic_checks()

        user_group_data = self.get_existing_usergroup()

        if user_group_data:
            if self.state == 'absent':
                self.log("CHANGED: user group exists, but requested state is 'absent'")
                changed = True
            elif self.state == 'present':
                # initiate probing
                modify = self.probe_user_group(user_group_data)
                if modify:
                    self.log("CHANGED: user group exists, but probe detected changes")
                    changed = True
        else:
            if self.state == 'present':
                self.log("CHANGED: user group does not exist, but requested state is 'present'")
                changed = True
        if changed:
            if self.state == 'present':
                if not user_group_data:
                    self.create_user_group()
                    msg = "User group [%s] has been created." % self.name
                else:
                    self.update_user_group(modify)
                    msg = "User group [%s] has been modified." % self.name
            elif self.state == 'absent':
                self.remove_user_group()
                msg = "User group [%s] has been removed." % self.name
            if self.module.check_mode:
                msg = "Skipping changes due to check mode."
        else:
            if self.state == 'absent':
                msg = "User group [%s] does not exist." % self.name
            elif self.state == 'present':
                msg = "User group [%s] already exist (no modificationes detected)." % self.name

        self.module.exit_json(msg=msg, changed=changed)


def main():
    v = IBMSVCUsergroup()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
