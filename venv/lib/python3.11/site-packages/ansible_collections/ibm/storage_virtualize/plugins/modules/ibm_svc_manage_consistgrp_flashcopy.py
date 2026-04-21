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
module: ibm_svc_manage_consistgrp_flashcopy
short_description: This module manages FlashCopy consistency groups on IBM Storage Virtualize
                   family systems
description:
  - Ansible interface to manage 'mkfcconsistgrp' and 'rmfcconsistgrp' volume commands.
version_added: "1.4.0"
options:
    name:
        description:
            - Specifies the name of the FlashCopy consistency group.
        required: true
        type: str
    state:
        description:
            - Creates (C(present)) or removes (C(absent)) a FlashCopy consistency group.
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
            - To generate a token, use the M(ibm.storage_virtualize.ibm_svc_auth) module.
        type: str
        version_added: '1.5.0'
    ownershipgroup:
        description:
            - Specifies the name of the ownership group.
            - Parameters I(ownershipgroup) and I(noownershipgroup) are mutually exclusive.
            - Valid when I(state=present), to create or modify a FlashCopy consistency group.
        required: false
        type: str
    noownershipgroup:
        description:
            - If specified True, the consistency group is removed from all associated ownership groups.
            - Parameters I(noownershipgroup) and I(ownershipgroup) are mutually exclusive.
            - Valid when I(state=present), to modify a FlashCopy consistency group.
        required: false
        type: bool
    force:
        description:
            - If specified True, removes all the associated FlashCopy mappings while deleting the FlashCopy consistency group.
            - Valid when I(state=absent), to delete a FlashCopy consistency group.
        required: false
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
    - Sreshtant Bohidar(@Sreshtant-Bohidar)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create a FlashCopy consistency group
  ibm.storage_virtualize.ibm_svc_manage_consistgrp_flashcopy:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: consistgroup-name
    state: present
    ownershipgroup: ownershipgroup-name
- name: Delete a FlashCopy consistency group
  ibm.storage_virtualize.ibm_svc_manage_consistgrp_flashcopy:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: consistgroup-name
    state: absent
    force: true
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCFlashcopyConsistgrp(object):
    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(type='str', required=True, choices=['present', 'absent']),
                ownershipgroup=dict(type='str', required=False),
                noownershipgroup=dict(type='bool', required=False),
                force=dict(type='bool', required=False),
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

        # Optional
        self.ownershipgroup = self.module.params.get('ownershipgroup', False)
        self.noownershipgroup = self.module.params.get('noownershipgroup', False)
        self.force = self.module.params.get('force', False)

        # Handling missing mandatory parameters name
        if not self.name:
            self.module.fail_json(msg='Missing mandatory parameter: name')

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

    def get_existing_fcconsistgrp(self):
        data = {}
        data = self.restapi.svc_obj_info(cmd='lsfcconsistgrp', cmdopts=None,
                                         cmdargs=[self.name])
        return data

    def fcconsistgrp_create(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'mkfcconsistgrp'
        cmdopts = {}
        cmdopts['name'] = self.name
        if self.ownershipgroup:
            cmdopts['ownershipgroup'] = self.ownershipgroup

        self.log("Creating fc consistgrp.. Command: %s opts %s", cmd, cmdopts)
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        if 'message' in result:
            self.changed = True
            self.log("Create fc consistgrp message %s", result['message'])
        else:
            self.module.fail_json(msg="Failed to create fc consistgrp [%s]" % self.name)

    def fcconsistgrp_delete(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'rmfcconsistgrp'
        cmdopts = {}
        if self.force:
            cmdopts['force'] = self.force

        self.log("Deleting fc consistgrp.. Command %s opts %s", cmd, cmdopts)
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=[self.name])

    def fcconsistgrp_probe(self, data):
        props = {}
        self.log("Probe which properties need to be updated...")
        if not self.noownershipgroup:
            if self.ownershipgroup and self.ownershipgroup != data["owner_name"]:
                props["ownershipgroup"] = self.ownershipgroup
        if self.noownershipgroup and data["owner_name"]:
            props['noownershipgroup'] = self.noownershipgroup
        return props

    def fcconsistgrp_update(self, modify):
        if self.module.check_mode:
            self.changed = True
            return

        if modify:
            self.log("updating fcmap with properties %s", modify)
            cmd = 'chfcconsistgrp'
            cmdopts = {}
            for prop in modify:
                cmdopts[prop] = modify[prop]

            cmdargs = [self.name]
            self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

    def apply(self):
        changed = False
        msg = None
        modify = []
        gdata = self.get_existing_fcconsistgrp()
        if gdata:
            if self.state == "absent":
                self.log("fc consistgrp [%s] exist, but requested state is 'absent'", self.name)
                changed = True
            elif self.state == "present":
                modify = self.fcconsistgrp_probe(gdata)
                if modify:
                    changed = True
        else:
            if self.state == "present":
                self.log("fc consistgrp [%s] doesn't exist, but requested state is 'present'", self.name)
                changed = True
        if changed:
            if self.state == "absent":
                self.fcconsistgrp_delete()
                msg = "fc consistgrp [%s] has been deleted" % self.name
            elif self.state == "present" and modify:
                self.fcconsistgrp_update(modify)
                msg = "fc consistgrp [%s] has been modified" % self.name
            elif self.state == "present" and not modify:
                self.fcconsistgrp_create()
                msg = "fc consistgrp [%s] has been created" % self.name

            if self.module.check_mode:
                msg = 'skipping changes due to check mode.'
        else:
            if self.state == "absent":
                msg = "fc consistgrp [%s] does not exist" % self.name
            elif self.state == "present":
                msg = "fc consistgrp [%s] already exists" % self.name

        self.module.exit_json(msg=msg, changed=changed)


def main():
    v = IBMSVCFlashcopyConsistgrp()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
