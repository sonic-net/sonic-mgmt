#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2024 IBM CORPORATION
# Author(s): Sumit Kumar Gupta <sumit.gupta16@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ibm_sv_manage_drive
short_description: This module manages drives on IBM Storage Virtualize family storage systems
description:
    - Ansible interface to manage drive-related operations.
version_added: "2.4.0"
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
    drive_state:
        description:
            - Specifies the desired usability state of the drive.
        choices: [ unused, candidate, spare, failed ]
        type: str
    task:
        description:
            - Specifies a task to be performed on drive.
        choices: [ format, certify, recover, erase, triggerdump ]
        type: str
    drive_id:
        description:
            - Specifies the drive id.
        required: true
        type: int
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
notes:
    - This module supports C(check_mode).
    - If error code I(CMMVC6624E) is returned after running a I(recover) task, most likely drive has already
      been recovered.
'''

EXAMPLES = r'''
- name: Change drive state to candidate
  ibm.storage_virtualize.ibm_sv_manage_drive:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   drive_id: 5
   drive_state: candidate
   log_path: /tmp/playbook.debug

- name: Format a drive
  ibm.storage_virtualize.ibm_sv_manage_drive:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   drive_id: 5
   task: format
   log_path: /tmp/playbook.debug

- name: Trigger a drive dump
  ibm.storage_virtualize.ibm_sv_manage_drive:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   drive_id: 5
   task: triggerdump
   log_path: /tmp/playbook.debug
'''

RETURN = r'''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (IBMSVCRestApi,
                                                                                           svc_argument_spec,
                                                                                           get_logger)
from ansible.module_utils._text import to_native


class IBMSVDriveMgmt(object):
    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                drive_state=dict(type='str', choices=['unused', 'candidate', 'spare', 'failed']),
                task=dict(type='str', choices=['format', 'certify', 'recover', 'erase', 'triggerdump']),
                drive_id=dict(type='int', required=True)
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

        # Required parameter(s)
        self.drive_id = self.module.params['drive_id']

        # Optional parameters
        self.drive_state = self.module.params['drive_state']
        self.task = self.module.params['task']
        self.msg = ""

        self.basic_checks()

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

    def basic_checks(self):
        if self.drive_id is None:
            # Mandatory parameter drive_id check
            self.module.fail_json(msg="Missing mandatory parameter: drive_id")
        if self.drive_state and self.task:
            # drive_state and task are mutually-exclusive
            self.module.fail_json(msg='Mutually exclusive parameters: drive_state and task')

    def exec_drive_cmd(self):
        cmd = 'chdrive'
        cmdopts = {}
        cmdargs = []
        cmdargs.append(self.drive_id)

        if self.task:
            # If task is to trigger dump, use triggerdrivedump instead of chdrive
            if self.task == 'triggerdump':
                cmd = 'triggerdrivedump'

            else:
                # For other tasks such as format, erase, certify, recover, check currently running tasks if any
                cmdopts['task'] = self.task
                currently_running_drive_task = self.restapi.svc_obj_info(
                    cmd='lsdriveprogress',
                    cmdopts=None,
                    cmdargs=cmdargs
                )
                task_list = ['format', 'certify', 'recover', 'erase']
                if currently_running_drive_task:
                    if self.task == currently_running_drive_task['task']:
                        # If same task is already running for this drive_id, declare success and return
                        self.msg = 'Task (%s) is already running on drive (%s).' % (self.task, self.drive_id)
                        return

                    if currently_running_drive_task['task'] in task_list:
                        # If any other tasks are being run, return SVC error
                        self.module.fail_json(msg="CMMVC6625E The command cannot be initiated"
                                              " because a task is in progress on the drive.")

            self.restapi.svc_run_command(cmd, cmdopts, cmdargs=cmdargs)
            self.msg = 'Task (%s) started on drive (%s).' % (self.task, self.drive_id)
            self.changed = True
            return

        if self.drive_state:
            cmdopts['use'] = self.drive_state
            result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
            if result == "":
                self.changed = True
                self.msg = "Drive usability state changed successfully for drive ID %s." % self.drive_id
        else:
            # Show SVC error message to user
            self.module.fail_json(msg=result, changed=False)
        return

    def apply(self):
        msg = None
        if self.module.check_mode:
            self.basic_checks()
            self.changed = True
        else:
            self.exec_drive_cmd()
        self.module.exit_json(msg=self.msg, changed=self.changed)


def main():
    v = IBMSVDriveMgmt()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
