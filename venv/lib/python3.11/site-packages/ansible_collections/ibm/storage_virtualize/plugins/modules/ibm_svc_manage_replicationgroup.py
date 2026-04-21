#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2020 IBM CORPORATION
# Author(s): Rohit Kumar <rohit.kumar6@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_manage_replicationgroup
short_description: This module manages remote copy consistency group on
                   IBM Storage Virtualize family systems
version_added: "1.3.0"
description:
  - Ansible interface to manage 'mkrcconsistgrp', 'chrcconsistgrp', and 'rmrcconsistgrp'
    remote copy consistency group commands.
options:
    name:
        description:
            - Specifies the name for the new consistency group.
        required: true
        type: str
    state:
        description:
            - Creates or updates (C(present)) removes (C(absent))
              a consistency group.
        choices: [ absent, present ]
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
        version_added: '1.5.0'
    log_path:
        description:
            - Path of debug log file.
        type: str
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
    remotecluster:
        description:
            - Specifies the name of the remote system.
              Only used while creating a consistency group.
        type: str
    force:
        description:
            - If used to delete a consistency group,
              it specifies that you want the system to remove any
              relationship that belongs to the consistency
              group before the group is deleted.
            - If used to start a consistency group,
              it specifies that you want the system to process the
              copy operation even if it causes a temporary loss of
              consistency during synchronization.
            - It is required if the consistency group is in the ConsistentStopped
              state, but is not synchronized or is in the idling state -
              except if consistency protection is configured.
        type: bool
    copytype:
        description:
            - Specifies the mirror type of the remote copy. 'metro' means MetroMirror, 'global' means GlobalMirror.
            - If not specified, a MetroMirror remote copy will be created when creating a remote copy I(state=present).
        type: str
        choices: [ 'metro', 'global' ]
    cyclingmode:
        description:
            - Specifies the behavior of Global Mirror for the relationship.
            - Active-active relationships and relationships with cycling modes set to Multiple must always be configured with change volumes.
            - Applies when I(state=present) and I(copytype=global).
        type: str
        choices: [ 'multi', 'none' ]
    cyclingperiod:
        description:
            - Specifies the cycle period in seconds.
        type: int
author:
    - rohit(@rohitk-github)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Define a new rc consistency group
  ibm.storage_virtualize.ibm_svc_manage_replicationgroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: rccg4test
    remotecluster: remotecluster
    state: present
- name: Delete rc consistency group
  ibm.storage_virtualize.ibm_svc_manage_replicationgroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: rccg4test
    force: true
    state: absent
- name: Update rc consistency group
  ibm.storage_virtualize.ibm_svc_manage_replicationgroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: rccg4test
    cyclingperiod: 60
    state: present
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import \
    IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCRCCG(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(type='str', required=True, choices=['absent',
                                                               'present']),
                remotecluster=dict(type='str', required=False),
                force=dict(type='bool', required=False),
                copytype=dict(type='str', choices=['metro', 'global']),
                cyclingmode=dict(type='str', required=False, choices=['multi', 'none']),
                cyclingperiod=dict(type='int', required=False)
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required
        self.name = self.module.params['name']
        self.state = self.module.params['state']

        # Optional
        self.cluster = self.module.params.get('remotecluster', None)
        self.force = self.module.params.get('force', False)
        self.copytype = self.module.params.get('copytype', None)
        self.cyclingmode = self.module.params.get('cyclingmode', None)
        self.cyclingperiod = self.module.params.get('cyclingperiod', None)

        # Handling missing mandatory paratmeter name
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

    def get_existing_rccg(self):
        merged_result = {}

        data = self.restapi.svc_obj_info(cmd='lsrcconsistgrp', cmdopts=None,
                                         cmdargs=[self.name])

        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        return merged_result

    def rccg_probe(self, data):
        props = {}
        propscv = {}
        if self.copytype and self.copytype != data['copy_type']:
            if self.copytype == 'global':
                props['global'] = True
            elif self.copytype == 'metro':
                props['metro'] = True
            else:
                self.module.fail_json(msg="Unsupported mirror type: %s. Only 'global' and 'metro' are supported when modifying" % self.copytype)

        if self.copytype == 'global' and self.cyclingperiod and self.cyclingperiod != int(data['cycle_period_seconds']):
            propscv['cycleperiodseconds'] = self.cyclingperiod
        if self.copytype == 'global' and self.cyclingmode and self.cyclingmode != data['cycling_mode']:
            propscv['cyclingmode'] = self.cyclingmode

        return props, propscv

    def rccg_create(self):
        if self.module.check_mode:
            self.changed = True
            return

        rccg_data = self.get_existing_rccg()
        if rccg_data:
            self.rccg_update(rccg_data)
        self.log("creating rc consistgrp '%s'", self.name)

        # Make command
        cmd = 'mkrcconsistgrp'
        cmdopts = {'name': self.name}
        if self.cluster:
            cmdopts['cluster'] = self.cluster

        self.log("creating rc consistgrp command '%s' opts", self.cluster)

        # Run command
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log("create rc consistgrp result '%s'", result)
        msg = "succeeded to create rc consistgrp '%s'" % self.name
        self.log(msg)

        if 'message' in result:
            self.log("create rc consistgrp result message '%s'",
                     result['message'])
            self.module.exit_json(msg="rc consistgrp '%s' is created" %
                                      self.name, changed=True)

        else:
            self.module.fail_json(msg=result)

    def rccg_update(self, modify, modifycv):

        if modify:
            self.log("updating chrcconsistgrp with properties %s", modify)
            cmd = 'chrcconsistgrp'
            cmdopts = {}
            for prop in modify:
                cmdopts[prop] = modify[prop]
            cmdargs = [self.name]

            self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

            # Any error would have been raised in svc_run_command
            # chrcconsistgrp does not output anything when successful.
            self.changed = True
        if modifycv:
            self.log("updating chrcconsistgrp with properties %s", modifycv)
            cmd = 'chrcconsistgrp'
            cmdargs = [self.name]
            for prop in modifycv:
                cmdopts = {}
                cmdopts[prop] = modifycv[prop]
                self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

            # Any error would have been raised in svc_run_command
            # chrcconsistgrp does not output anything when successful.
            self.changed = True
        if not modify and not modifycv:
            self.log("There is no property to be updated")
            self.changed = False

    def rccg_delete(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("deleting rc consistgrp '%s'", self.name)

        cmd = 'rmrcconsistgrp'
        cmdopts = {'force': True} if self.force else None
        cmdargs = [self.name]

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # rmrcconsistgrp does not output anything when successful.
        msg = "rc consistgrp '%s' is deleted" % self.name
        self.log(msg)
        self.module.exit_json(msg=msg, changed=True)

    def apply(self):
        changed = False
        msg = None
        modify = {}
        rccg_data = self.get_existing_rccg()
        if rccg_data:
            if self.state == 'absent':
                self.log(
                    "CHANGED: RemoteCopy group exists, requested state is 'absent'")
                changed = True
            elif self.state == 'present':
                modify, modifycv = self.rccg_probe(rccg_data)
                if modify or modifycv:
                    changed = True
        else:
            if self.state == 'present':
                if self.copytype:
                    self.module.fail_json(msg="copytype cannot be passed while creating a consistency group")
                changed = True
                self.log(
                    "CHANGED: Remotecopy group does not exist, but requested state is '%s'", self.state)
        if changed:
            if self.state == 'present':
                if not rccg_data:
                    self.rccg_create()
                    msg = "remote copy group %s has been created." % self.name
                else:
                    self.rccg_update(modify, modifycv)
                    msg = "remote copy group [%s] has been modified." % self.name
            elif self.state == 'absent':
                self.rccg_delete()
                msg = "remote copy group [%s] has been deleted." % self.name

            if self.module.check_mode:
                msg = 'skipping changes due to check mode.'
        else:
            self.log("exiting with no changes")
            if self.state in ['absent']:
                msg = "Remotecopy group [%s] does not exist." % self.name
            else:
                msg = "No Modifications detected, Remotecopy group [%s] already exists." % self.name

        self.module.exit_json(msg=msg, changed=changed)


def main():
    v = IBMSVCRCCG()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
