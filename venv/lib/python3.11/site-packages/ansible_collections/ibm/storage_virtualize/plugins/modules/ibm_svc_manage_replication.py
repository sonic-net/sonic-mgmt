#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2020 IBM CORPORATION
# Author(s): Rohit Kumar <rohit.kumar6@ibm.com>
#            Shilpi Jain <shilpi.jain1@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_manage_replication
short_description: This module manages remote copies (or rcrelationship) on
                   IBM Storage Virtualize family systems
version_added: "1.3.0"

description:
  - Ansible interface to manage remote copy replication.

options:
  name:
    description:
      - Specifies the name to assign to the new remote copy relationship or to operate on the existing remote copy.
    type: str
  state:
    description:
      - Creates or updates (C(present)), removes (C(absent)) a
        remote copy relationship.
    choices: [absent, present]
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
  copytype:
    description:
    - Specifies the mirror type of the remote copy. 'metro' means MetroMirror,
      'global' means GlobalMirror, and 'GMCV' means GlobalMirror with change volume.
    - If not specified, a MetroMirror remote copy will be created when creating a remote copy I(state=present).
    type: str
    choices: [ 'metro', 'global' , 'GMCV']
  master:
    description:
    - Specifies the master volume name when creating a remote copy.
    type: str
  aux:
    description:
    - Specifies the auxiliary volume name when creating a remote copy.
    type: str
  cyclingperiod:
    description:
    - Specifies the cycle period in seconds. The default cycle is of 300 seconds.
    type: int
  remotecluster:
    description:
    - Specifies the name of remote cluster when creating a remote copy.
    type: str
  sync:
    description:
    - Specifies whether to create a synchronized relationship.
    default: false
    type: bool
  force:
    description:
    - Specifies that the relationship must be deleted even if it results in the secondary volume containing inconsistent data.
    type: bool
  consistgrp:
    description:
    - Specifies a consistency group that this relationship will join. If not specified by user, the relationship is created as a stand-alone relationship.
    - Applies when I(state=present).
    type: str
  noconsistgrp:
    description:
    - Specifies whether to remove the specified relationship from a consistency
      group, making the relationship a stand-alone relationship.
    - Applies when I(state=present).
    default: false
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
notes:
  - The parameters I(primary) and I(aux) are mandatory only when a remote copy relationship does not exist.
  - This module supports C(check_mode).
  - Parameters copytype, cyclingperiod are not supported for update operation when the relationship is a part of consistency group.
    In case these parameters are specified, Ansible will return the following error,
    "CMMVC5951E Individual relationship cannot be updated while it is part of a consistency group."
  - Only one update operation is supported in a single task for remote copy relationships, if multiple are detected, Ansible will return the following error,
    "CMMVC5713E Only 1 update operation supported in one task"
author:
    - rohit(@rohitk-github)
    - Shilpi Jain (@Shilpi-Jain1)
'''

EXAMPLES = '''
- name: Create remote copy
  ibm.storage_virtualize.ibm_svc_manage_replication:
    name: sample_rcopy
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    state: present
    remotecluster: "{{ remotecluster }}"
    master: SourceVolume0
    aux: TargetVolume0
    copytype: global
    sync: true
    consistgrp: sample_rccg
  register: result
- name: Exclude the remote copy from consistency group
  ibm.storage_virtualize.ibm_svc_manage_replication:
    name: sample_rcopy2
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    state: present
    noconsistgrp: true
- name: Delete remote copy
  ibm.storage_virtualize.ibm_svc_manage_replication:
    name: sample_rcopy3
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    state: absent
- name: Create GlobalMirror remote copy relationship with change volume
  ibm.storage_virtualize.ibm_svc_manage_replication:
    name: sample_rcopy4
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    state: present
    remotecluster: "{{ remotecluster }}"
    master: SourceVolume1
    aux: TargetVolume1
    copytype: GMCV
    sync: true
  register: result
'''

RETURN = '''#'''


from ansible.module_utils._text import to_native
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils.basic import AnsibleModule
from traceback import format_exc


class IBMSVCManageReplication(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                name=dict(type='str'),
                state=dict(type='str',
                           required=True,
                           choices=['present', 'absent']),
                remotecluster=dict(type='str'),
                copytype=dict(type='str', choices=['metro', 'global', 'GMCV']),
                master=dict(type='str'),
                aux=dict(type='str'),
                force=dict(type='bool', required=False),
                consistgrp=dict(type='str'),
                noconsistgrp=dict(type='bool', default=False),
                sync=dict(type='bool', default=False),
                cyclingperiod=dict(type='int')
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
        self.remotecluster = self.module.params['remotecluster']

        # Optional
        self.consistgrp = self.module.params.get('consistgrp', None)
        self.aux = self.module.params.get('aux')
        self.master = self.module.params.get('master')
        self.sync = self.module.params.get('sync', False)
        self.noconsistgrp = self.module.params.get('noconsistgrp', False)
        self.copytype = self.module.params.get('copytype', None)
        self.force = self.module.params.get('force', False)
        self.cyclingperiod = self.module.params.get('cyclingperiod')

        # Handling missing mandatory parameter name
        if not self.name:
            self.module.fail_json(msg='Missing mandatory parameter: name')

        if self.consistgrp and self.noconsistgrp:
            self.module.fail_json(msg='Mutually exclusive parameters: consistgrp and noconsistgrp')

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

    def existing_vdisk(self, volname):
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

    def cycleperiod_update(self):
        """
        Use the chrcrelationship command to update cycling period in remote copy
        relationship.
        """
        if self.module.check_mode:
            self.changed = True
            return

        if (self.copytype == 'GMCV') and (self.cyclingperiod):
            cmd = 'chrcrelationship'
            cmdopts = {}
            cmdopts['cycleperiodseconds'] = self.cyclingperiod
            cmdargs = [self.name]

            self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
        else:
            self.log("not updating chrcrelationship with cyclingperiod %s", self.cyclingperiod)

    def cyclemode_update(self):
        """
        Use the chrcrelationship command to update cycling mode in remote copy
        relationship.
        """
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'chrcrelationship'
        cmdopts = {}
        cmdargs = [self.name]

        if self.copytype == 'GMCV':
            self.log("updating chrcrelationship with cyclingmode multi")
            cmdopts['cyclingmode'] = 'multi'
        else:
            self.log("updating chrcrelationship with no cyclingmode")
            cmdopts['cyclingmode'] = 'none'

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

    def existing_rc(self):
        """
        find the remote copy relationships such as Metro Mirror, Global Mirror
        relationships visible to the system.

        Returns:
            None if no matching instances or a list including all the matching
            instances
        """
        self.log('Trying to get the remote copy relationship %s', self.name)
        data = self.restapi.svc_obj_info(cmd='lsrcrelationship',
                                             cmdopts=None, cmdargs=[self.name])

        return data

    def rcrelationship_probe(self, data):
        props = {}
        propscv = {}
        relationship_in_cg_error = "CMMVC5951E Individual relationship cannot be updated while it is part of a consistency group."
        if data['consistency_group_name']:
            if self.cyclingperiod and self.cyclingperiod != data['cycle_period_seconds']:
                self.module.fail_json(msg=relationship_in_cg_error)
            if self.copytype:
                if self.copytype == 'GMCV':
                    if (data['copy_type'] != 'global' or data['cycling_mode'] != 'multi'):
                        self.module.fail_json(msg=(relationship_in_cg_error))
                elif self.copytype == 'global':
                    if (data['copy_type'] != 'global' or data['cycling_mode'] != 'none'):
                        self.module.fail_json(msg=relationship_in_cg_error)
                elif self.copytype and self.copytype != data['copy_type']:
                    self.module.fail_json(msg=relationship_in_cg_error)
        if self.master is not None and self.master != data['master_vdisk_name']:
            self.module.fail_json(msg="Parameter not supported for update operation: master")
        if self.aux is not None and self.aux != data['aux_vdisk_name']:
            self.module.fail_json(msg="Parameter not supported for update operation: aux")
        if data['consistency_group_name'] and self.noconsistgrp:
            props['noconsistgrp'] = self.noconsistgrp
        if self.consistgrp is not None and self.consistgrp != data['consistency_group_name']:
            props['consistgrp'] = self.consistgrp
        if self.copytype == 'global' and data['copy_type'] == 'metro':
            props['global'] = True

        if (self.copytype == 'metro' or self.copytype is None) and (data['copy_type'] == 'global' and data['cycling_mode'] == 'multi'):
            self.module.fail_json(msg="Changing relationship type from GMCV to metro is not allowed")
        elif (self.copytype == 'metro' or self.copytype is None) and data['copy_type'] == 'global':
            props['metro'] = True

        if self.copytype == 'GMCV' and data['copy_type'] == 'global':
            if data['cycling_mode'] != 'multi':
                propscv['cyclingmode'] = 'multi'
            if self.cyclingperiod is not None and self.cyclingperiod != int(data['cycle_period_seconds']):
                propscv['cycleperiodseconds'] = self.cyclingperiod
        if self.copytype == 'global' and (data['copy_type'] == 'global' and data['cycling_mode'] == 'multi'):
            propscv['cyclingmode'] = 'none'
        if self.copytype == 'GMCV' and data['copy_type'] == 'metro':
            self.module.fail_json(msg="Changing relationship type from metro to GMCV is not allowed")
        if self.copytype != 'metro' and self.copytype != 'global' and self.copytype != 'GMCV' and self.copytype is not None:
            self.module.fail_json(msg="Unsupported mirror type: %s. Only 'global', 'metro' and 'GMCV' are supported when modifying" % self.copytype)
        if len(props) > 1:
            self.module.fail_json(msg=f"CMMVC5713E Only 1 update operation supported in one task, {len(props)} operations detected: {props}")
        return props, propscv

    def rcrelationship_update(self, modify, modifycv):
        """
        Use the chrcrelationship command to modify certain attributes of an
        existing relationship, such as to add a relationship to a consistency
        group to remove a relationship from a consistency group.
        You can change one attribute at a time.
        """
        if self.module.check_mode:
            self.changed = True
            return

        if modify:
            self.log("updating chrcrelationship with properties %s", modify)
            cmd = 'chrcrelationship'
            cmdopts = {}
            for prop in modify:
                cmdopts[prop] = modify[prop]
            cmdargs = [self.name]

            self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

            # Error(if any) will be raised in svc_run_command
            self.changed = True
        if modifycv:
            if 'cycleperiodseconds' in modifycv:
                self.cycleperiod_update()
                self.log("cyclingperiod in change volume updated")
            if 'cyclingmode' in modifycv:
                self.cyclemode_update()
                self.log("cyclingmode in change volume updated")
            # Error(if any) will be raised in svc_run_command
            self.changed = True
        if not modify and not modifycv:
            self.log("There is no property need to be updated")
            self.changed = False

    def create(self):
        """
        Specify the mkrcrelationship command to create a new Global Mirror,
        Metro Mirror in the same system, forming an intrasystem Metro Mirror
        relationship or intersystem
        relationship (if it involves more than one system).

        Returns:
            a remote copy instance
        """
        if not self.name:
            self.module.fail_json(msg="You must pass in name to the module.")
        if not self.master:
            self.module.fail_json(msg="You must pass in master to the module.")
        if not self.aux:
            self.module.fail_json(msg="You must pass in aux to the module.")
        if not self.remotecluster:
            self.module.fail_json(msg="You must pass in remotecluster to the module.")

        if self.module.check_mode:
            self.changed = True
            return

        self.log("Creating remote copy '%s'", self.name)

        # Make command
        cmd = 'mkrcrelationship'
        cmdopts = {}
        if self.remotecluster:
            cmdopts['cluster'] = self.remotecluster
        if self.master:
            cmdopts['master'] = self.master
        if self.aux:
            cmdopts['aux'] = self.aux
        if self.name:
            cmdopts['name'] = self.name

        if self.copytype:
            if self.copytype == 'global' or self.copytype == 'GMCV':
                cmdopts['global'] = True
                if self.copytype == 'GMCV':
                    cmdopts['cyclingmode'] = 'multi'
            elif self.copytype == 'metro' or self.copytype == 'blank':
                pass
            else:
                msg = "Invalid parameter specified as the Copy Type(%s) when creating Remotecopy" % self.copytype
                self.module.fail_json(msg=msg)

        if self.copytype != 'GMCV' and self.cyclingperiod is not None:
            msg = "Provided copytype is %s. Copy Type must be GMCV when creating Remotecopy relationship with change volumes and cycling period" % self.copytype
            self.module.fail_json(msg=msg)

        if self.consistgrp:
            cmdopts['consistgrp'] = self.consistgrp
        if self.sync:
            cmdopts['sync'] = self.sync

        # Run command
        self.log("Command %s opts %s", cmd, cmdopts)
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log("create remote copy result %s", result)

        if 'message' in result:
            self.changed = True
            data = self.existing_rc()
            self.log("Succeeded to create remote copy result message %s",
                     result['message'])
            return data
        else:
            msg = "Failed to create remote copy [%s]" % self.name
            self.module.fail_json(msg=msg)

    def delete(self):
        """
        Use the rmrcrelationship command to delete an existing remote copy
        relationship.
        """
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'rmrcrelationship'
        cmdopts = {}
        if self.force:
            cmdopts['force'] = self.force
        cmdargs = [self.name]

        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # Command does not output anything when successful.
        if result == '':
            self.changed = True
            self.log("succeeded to delete the remote copy %s", self.name)
        elif 'message' in result:
            self.changed = True
            self.log("delete the remote copy %s with result message %s",
                     self.name, result['message'])
        else:
            self.module.fail_json(
                msg="Failed to delete the remote copy [%s]" % self.name)

    def apply(self):
        changed = False
        msg = None
        modify = {}
        modifycv = {}
        rcrelationship_data = self.existing_rc()
        if rcrelationship_data:
            if self.state == 'absent':
                self.log(
                    "CHANGED: RemoteCopy relationship exists, requested state is 'absent'")
                changed = True
            elif self.state == 'present':
                modify, modifycv = self.rcrelationship_probe(rcrelationship_data)
                if modify or modifycv:
                    changed = True
        else:
            if self.state == 'present':
                changed = True
                self.log(
                    "CHANGED: Remotecopy relationship does not exist, but requested state is '%s'", self.state)

        if changed:
            if self.state == 'present':
                if not rcrelationship_data:
                    self.create()
                    if self.copytype == 'GMCV' and self.consistgrp is None:
                        self.cycleperiod_update()
                        self.cyclemode_update()
                        msg = "remote copy relationship with change volume %s has been created." % self.name
                    else:
                        msg = "remote copy relationship %s has been created." % self.name
                else:
                    self.rcrelationship_update(modify, modifycv)
                    msg = "remote copy relationship [%s] has been modified." % self.name
            elif self.state == 'absent':
                self.delete()
                msg = "remote copy relationship [%s] has been deleted." % self.name

            if self.module.check_mode:
                msg = 'skipping changes due to check mode.'
        else:
            self.log("exiting with no changes")
            if self.state in ['absent']:
                msg = "Remotecopy relationship [%s] does not exist." % self.name
            else:
                msg = "No Modifications detected, Remotecopy relationship [%s] already exists." % self.name

        self.module.exit_json(msg=msg, changed=changed)


def main():
    v = IBMSVCManageReplication()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
