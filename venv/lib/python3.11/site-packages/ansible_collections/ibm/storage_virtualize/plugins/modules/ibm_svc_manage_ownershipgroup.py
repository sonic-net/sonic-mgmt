#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 IBM CORPORATION
# Author(s): Sanjaikumaar <sanjaikumaar.m@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_manage_ownershipgroup
short_description: This module manages ownership group on IBM Storage Virtualize family systems
version_added: "1.7.0"
description:
  - Ansible interface to manage 'mkownershipgroup' and 'rmownershipgroup' commands.
options:
    name:
        description:
            - Specifies the name or label for the new ownership group object.
        required: true
        type: str
    state:
        description:
            - Creates (C(present)) or removes (C(absent)) an ownership group.
        choices: [ absent, present ]
        required: true
        type: str
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
    keepobjects:
        description:
            - If specified, the objects that currently belong to the ownership group will be kept but will be moved to noownershipgroup.
            - Applies when I(state=disabled).
        type: bool
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
    - Sanjaikumaar M (@sanjaikumaar)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create ownership group
  ibm.storage_virtualize.ibm_svc_manage_ownershipgroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: newOwner
    state: present
- name: Delete ownership group
  ibm.storage_virtualize.ibm_svc_manage_ownershipgroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: newOwner
    state: absent
    keepobjects: true
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (
    IBMSVCRestApi,
    svc_argument_spec,
    get_logger
)


class IBMSVCOwnershipgroup:

    def __init__(self):
        # Gathering required arguments for the module
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(
                    type='str',
                    required=True,
                    choices=['present', 'absent']
                ),
                keepobjects=dict(type='bool')
            )
        )

        # Initializing ansible module
        self.module = AnsibleModule(
            argument_spec=argument_spec,
            supports_check_mode=True
        )

        # Required parameters
        self.name = self.module.params['name']
        self.state = self.module.params['state']

        # Optional parameters
        self.keepobjects = self.module.params.get('keepobjects')

        if not self.name:
            self.module.fail_json(msg='Missing mandatory parameter: name')

        # logging setup
        log_path = self.module.params['log_path']
        logger = get_logger(self.__class__.__name__, log_path)
        self.log = logger.info
        self.changed = False
        self.msg = None

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

    def check_existing_owgroups(self):
        merged_result = {}

        data = self.restapi.svc_obj_info(cmd='lsownershipgroup', cmdopts=None,
                                         cmdargs=[self.name])

        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        return merged_result

    def create_ownershipgroup(self):
        if self.module.check_mode:
            self.changed = True
            return

        if self.keepobjects:
            self.module.fail_json(
                msg='Keepobjects should only be passed while deleting ownershipgroup'
            )

        cmd = 'mkownershipgroup'
        cmdopts = None
        cmdargs = ['-name', self.name]

        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
        self.changed = True
        self.log('Create ownership group result: %s', result)

    def delete_ownershipgroup(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'rmownershipgroup'
        cmdopts = None
        cmdargs = [self.name]

        if self.keepobjects:
            cmdargs.insert(0, '-keepobjects')

        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
        self.changed = True
        self.log('Delete ownership group result: %s', result)

    def apply(self):
        if self.check_existing_owgroups():
            if self.state == 'present':
                self.msg = 'Ownership group (%s) already exist.' % (self.name)
            else:
                self.delete_ownershipgroup()
                self.msg = 'Ownership group (%s) deleted.' % (self.name)
        else:
            if self.state == 'absent':
                self.msg = 'Ownership group (%s) does not exist.' % (self.name)
            else:
                self.create_ownershipgroup()
                self.msg = 'Ownership group (%s) created.' % \
                           (self.name)

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'

        self.module.exit_json(
            changed=self.changed,
            msg=self.msg
        )


def main():
    v = IBMSVCOwnershipgroup()
    try:
        v.apply()
    except Exception as e:
        v.log('Exception in apply(): \n%s', format_exc())
        v.module.fail_json(msg='Module failed. Error [{0}].'.format(to_native(e)))


if __name__ == '__main__':
    main()
