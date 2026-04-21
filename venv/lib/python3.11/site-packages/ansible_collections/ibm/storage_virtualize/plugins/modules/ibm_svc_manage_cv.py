#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2020 IBM CORPORATION
# Author(s): Shilpi Jain <shilpi.jain1@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_manage_cv
short_description: This module manages the change volume for a given volume on IBM
                   Storage Virtualize family systems
description:
  - Ansible interface to manage the change volume in remote copy replication on IBM Storage Virtualize family systems.
version_added: "1.3.0"
options:
  state:
    description:
      - Creates or updates (C(present)) or removes (C(absent)), a change volume.
    choices: [absent, present]
    required: true
    type: str
  rname:
    description:
      - Specifies the name of the remote copy relationship.
    required: true
    type: str
  cvname:
    description:
      - Specifies the name to assign to the master or auxiliary change volume.
    required: true
    type: str
  basevolume:
    description:
    - Specifies the base volume name (master or auxiliary).
    - Required when I(state=present), to create the change volume.
    type: str
  ismaster:
    description:
      - Specifies whether the change volume is being (dis)associated with master cluster.
      - Required when the change volume is being associated or disassociated from the master cluster.
    type: bool
    default: true
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
    - Shilpi Jain(@Shilpi-Jain1)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create master change volume and associate with rcopy
  ibm.storage_virtualize.ibm_svc_manage_cv:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    state: present
    rname: sample_rcopy
    cvname: vol1_cv
    basevolume: vol1
- name: Create auxiliary change volume and associate with rcopy
  ibm.storage_virtualize.ibm_svc_manage_cv:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    state: present
    rname: sample_rcopy
    cvname: vol2_aux_cv
    basevolume: vol2
    ismaster: false
- name: Delete master change volume and disassociate from rcopy
  ibm.storage_virtualize.ibm_svc_manage_cv:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    state: absent
    rname: sample_rcopy
    cvname: vol1_cv
- name: Delete auxiliary change volume and disassociate from rcopy
  ibm.storage_virtualize.ibm_svc_manage_cv:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    state: absent
    rname: sample_rcopy
    cvname: vol2_aux_cv
    ismaster: false
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCchangevolume(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                state=dict(type='str',
                           required=True,
                           choices=['present', 'absent']),
                rname=dict(type='str', required=True),
                cvname=dict(type='str', required=True),
                basevolume=dict(type='str'),
                ismaster=dict(type='bool', default=True)
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required
        self.state = self.module.params['state']
        self.rname = self.module.params['rname']
        self.cvname = self.module.params['cvname']

        # Optional
        self.basevolume = self.module.params['basevolume']
        self.ismaster = self.module.params['ismaster']

        # Handling missing mandatory parameter rname
        if not self.rname:
            self.module.fail_json(msg='Missing mandatory parameter: rname')
        # Handling missing mandatory parameter cvname
        if not self.cvname:
            self.module.fail_json(msg='Missing mandatory parameter: cvname')

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

    def get_existing_rc(self):
        """
        find the remote copy relationships such as Metro Mirror, Global Mirror
        relationships visible to the system.

        Returns:
            None if no matching instances or a list including all the matching
            instances
        """
        self.log('Trying to get the remote copy relationship %s', self.rname)
        data = self.restapi.svc_obj_info(cmd='lsrcrelationship',
                                             cmdopts=None, cmdargs=[self.rname])

        return data

    def get_existing_vdisk(self, volname):
        merged_result = {}

        data = self.restapi.svc_obj_info(cmd='lsvdisk', cmdopts={'bytes': True},
                                         cmdargs=[volname])

        if not data:
            self.log("source volume %s does not exist", volname)
            return

        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        return merged_result

    def change_volume_attach(self, rcrelationship_data):
        cmdopts = {}

        if rcrelationship_data['copy_type'] != 'global':
            self.module.fail_json(msg="Relationship '%s' type must be global" % self.rname)

        if self.ismaster:
            cmdopts['masterchange'] = self.cvname
        else:
            cmdopts['auxchange'] = self.cvname

        # command
        cmd = 'chrcrelationship'
        cmdargs = [self.rname]
        self.log("updating chrcrelationship %s with properties %s", cmd, cmdopts)

        # Run command
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        self.changed = True
        self.log("Updated remote copy relationship ")

    def change_volume_detach(self, rcrelationship_data):
        cmdopts = {}

        if self.ismaster:
            cmdopts = {'nomasterchange': True}
        else:
            cmdopts = {'noauxchange': True}

        # command
        cmd = 'chrcrelationship'
        cmdargs = [self.rname]
        self.log("updating chrcrelationship %s with properties %s", cmd, cmdopts)

        # Run command
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        self.changed = True
        self.log("Updated remote copy relationship ")

    def change_volume_probe(self):
        is_update_required = False

        rcrelationship_data = self.get_existing_rc()
        if not rcrelationship_data:
            self.module.fail_json(msg="Relationship '%s' does not exists, relationship must exists before calling this module" % self.rname)

        if self.ismaster:
            if self.cvname == rcrelationship_data['master_change_vdisk_name']:
                self.log("Master change volume %s is already attached to the relationship", self.cvname)
            elif rcrelationship_data['master_change_vdisk_name'] != '':
                self.module.fail_json(msg="Master change volume %s is already attached to the relationship" % rcrelationship_data['master_change_vdisk_name'])
            else:
                is_update_required = True
        else:
            if self.cvname == rcrelationship_data['aux_change_vdisk_name']:
                self.log("Aux change volume %s is already attached to the relationship", self.cvname)
            elif rcrelationship_data['aux_change_vdisk_name'] != '':
                self.module.fail_json(msg="Aux change volume %s is already attached to the relationship" % rcrelationship_data['aux_change_vdisk_name'])
            else:
                is_update_required = True

        return is_update_required

    def change_volume_delete(self):
        # command
        cmd = 'rmvolume'
        cmdopts = None
        cmdargs = [self.cvname]

        # Run command
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        self.changed = True
        self.log("Delete vdisk %s", self.cvname)

    def change_volume_create(self):
        if self.module.check_mode:
            self.changed = True
            return

        if not self.basevolume:
            self.module.fail_json(msg="You must pass in name of the master or auxiliary volume.")

        # lsvdisk <basevolume>
        vdisk_data = self.get_existing_vdisk(self.basevolume)
        if not vdisk_data:
            self.module.fail_json(msg="%s volume does not exist, change volume not created" % self.basevolume)

        # Make command
        cmd = 'mkvdisk'
        cmdopts = {}
        cmdopts['name'] = self.cvname
        cmdopts['mdiskgrp'] = vdisk_data['mdisk_grp_name']
        cmdopts['size'] = vdisk_data['capacity']
        cmdopts['unit'] = 'b'
        cmdopts['rsize'] = '0%'
        cmdopts['autoexpand'] = True
        cmdopts['iogrp'] = vdisk_data['IO_group_name']
        self.log("creating vdisk command %s opts %s", cmd, cmdopts)

        # Run command
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)

        if 'message' in result:
            self.changed = True
            self.log("Create vdisk result message %s", result['message'])
        else:
            self.module.fail_json(
                msg="Failed to create vdisk [%s]" % self.cvname)

    def apply(self):
        changed = False
        msg = None
        modify = []

        vdisk_data = self.get_existing_vdisk(self.cvname)

        if vdisk_data:
            if self.state == 'absent':
                self.log(
                    "CHANGED: Change volume exists, requested state is 'absent'")
                changed = True
            elif self.state == 'present':
                modify = self.change_volume_probe()
                if modify:
                    changed = True
                else:
                    self.log("No change detected")
        else:
            if self.state == 'present':
                changed = True
                self.log("CHANGED: Change volume does not exist, but requested state is '%s'", self.state)

        if changed:
            if self.module.check_mode:
                msg = 'skipping changes due to check mode.'
            else:
                rcrelationship_data = self.get_existing_rc()
                if not rcrelationship_data:
                    self.module.fail_json(msg="Relationship '%s' does not exists, relationship must exists before calling this module" % self.rname)
                else:
                    if self.state == 'present' and modify:
                        self.change_volume_attach(rcrelationship_data)
                        msg = "Change volume %s configured to the remote copy relationship." % self.cvname
                    elif self.state == 'present':
                        self.change_volume_create()
                        self.change_volume_attach(rcrelationship_data)
                        msg = "vdisk %s has been created and configured to remote copy relationship." % self.cvname
                    elif self.state == 'absent':
                        self.change_volume_detach(rcrelationship_data)
                        self.change_volume_delete()
                        msg = "vdisk %s has been deleted and detached from remote copy relationship." % self.cvname
        else:
            self.log("Exiting with no changes")
            if self.state in ['absent']:
                msg = "Change volume [%s] does not exist." % self.cvname
            else:
                msg = "No Modifications detected, Change volume [%s] already configured." % self.cvname

        self.module.exit_json(msg=msg, changed=changed)


def main():
    v = IBMSVCchangevolume()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
