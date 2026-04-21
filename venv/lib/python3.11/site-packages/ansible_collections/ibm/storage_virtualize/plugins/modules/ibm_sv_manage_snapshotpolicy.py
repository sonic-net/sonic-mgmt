#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2022 IBM CORPORATION
# Author(s): Shilpi Jain <shilpi.jain1@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_sv_manage_snapshotpolicy
short_description: This module manages snapshot policy configuration on IBM Storage Virtualize family systems
version_added: "1.9.0"
description:
  - Ansible interface to manage 'mksnapshotpolicy' and 'rmsnapshotpolicy' snapshot policy commands.
  - Snapshot policy is introduced in IBM Storage Virtualize 8.5.1.0.
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
            - Creates (C(present)) or deletes (C(absent)) a snapshot policy.
            - Resume (C(resume)) or suspend (C(suspend)) the snapshot policy, system-wide.
        choices: [ present, absent, suspend, resume ]
        required: true
        type: str
    name:
        description:
            - Specifies a unique name of the snapshot policy.
            - Not applicable when I(state=suspend) or I(state=resume).
        type: str
    backupunit:
        description:
            - Specifies the backup unit in mentioned metric.
            - Applies when I(state=present).
        choices: [ minute, hour, day, week, month ]
        type: str
    backupinterval:
        description:
            - Specifies the backup interval.
            - Applies when I(state=present).
        type: str
    backupstarttime:
        description:
            - Specifies the start time of backup in the format YYMMDDHHMM.
            - Applies when I(state=present).
        type: str
    retentiondays:
        description:
            - Specifies the retention days for the backup.
            - Applies when I(state=present).
        type: str
    removefromvolumegroups:
        description:
            - Specify to remove the volume group association from the snapshot policy.
            - Applies when I(state=absent).
            - This option is allowed only for SecurityAdmin users.
        type: bool
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
author:
    - Shilpi Jain(@Shilpi-J)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create snapshot policy
  ibm.storage_virtualize.ibm_sv_manage_snapshotpolicy:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: policy0
    backupunit: day
    backupinterval: 1
    backupstarttime: 2102281800
    retentiondays: 15
    state: present
- name: Suspend snapshot policy functionality
  ibm.storage_virtualize.ibm_sv_manage_snapshotpolicy:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    state: suspend
- name: Resume snapshot policy functionality
  ibm.storage_virtualize.ibm_sv_manage_snapshotpolicy:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    state: resume
- name: Delete snapshot policy
  ibm.storage_virtualize.ibm_sv_manage_snapshotpolicy:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: policy0
    state: absent
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (
    IBMSVCRestApi, svc_argument_spec,
    get_logger
)
from ansible.module_utils._text import to_native


class IBMSVCSnapshotPolicy:

    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                state=dict(
                    type='str',
                    required=True,
                    choices=['present', 'absent', 'suspend', 'resume']
                ),
                name=dict(
                    type='str',
                ),
                backupunit=dict(
                    type='str',
                    choices=['minute', 'hour', 'day', 'week', 'month'],
                ),
                backupinterval=dict(
                    type='str',
                ),
                backupstarttime=dict(
                    type='str',
                ),
                retentiondays=dict(
                    type='str',
                ),
                removefromvolumegroups=dict(
                    type='bool'
                ),
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # Required parameters
        self.name = self.module.params['name']
        self.state = self.module.params['state']
        self.backupunit = self.module.params.get('backupunit', '')
        self.backupinterval = self.module.params.get('backupinterval', '')
        self.backupstarttime = self.module.params.get('backupstarttime', '')
        self.retentiondays = self.module.params.get('retentiondays', '')
        self.removefromvolumegroups = self.module.params.get('removefromvolumegroups', False)

        self.basic_checks()

        # Variable to cache data
        self.snapshot_policy_details = None

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
        if self.state == 'present':
            fields = ['name', 'backupinterval', 'backupstarttime', 'retentiondays', 'backupunit']
            exists = list(filter(lambda x: not getattr(self, x), fields))

            if any(exists):
                self.module.fail_json(
                    msg="State is present but following parameters are missing: {0}".format(', '.join(exists))
                )

            if self.removefromvolumegroups:
                self.module.fail_json(
                    msg="`removefromvolumegroups` parameter is not supported when state=present"
                )
        elif self.state == 'absent':
            if not self.name:
                self.module.fail_json(msg="Missing mandatory parameter: name")

            fields = ['backupinterval', 'backupstarttime', 'retentiondays', 'backupunit']
            exists = list(filter(lambda x: getattr(self, x) or getattr(self, x) == '', fields))

            if any(exists):
                self.module.fail_json(msg='{0} should not be passed when state=absent'.format(', '.join(exists)))
        elif self.state in ['suspend', 'resume']:
            fields = ['name', 'backupinterval', 'backupstarttime', 'retentiondays', 'backupunit']
            exists = list(filter(lambda x: getattr(self, x) or getattr(self, x) == '', fields))

            if any(exists):
                self.module.fail_json(msg='{0} should not be passed when state={1}'.format(', '.join(exists), self.state))

    def policy_exists(self):
        merged_result = {}
        data = self.restapi.svc_obj_info(
            cmd='lssnapshotschedule',
            cmdopts=None,
            cmdargs=[self.name]
        )
        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        self.snapshot_policy_details = merged_result

        return merged_result

    def create_snapshot_policy(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'mksnapshotpolicy'
        cmdopts = {
            'name': self.name,
            'backupstarttime': self.backupstarttime,
            'backupinterval': self.backupinterval,
            'backupunit': self.backupunit,
            'retentiondays': self.retentiondays
        }

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log('Snapshot policy (%s) created', self.name)
        self.changed = True

    def snapshot_policy_probe(self):
        field_mappings = (
            ('backupinterval', self.snapshot_policy_details['backup_interval']),
            ('backupstarttime', self.snapshot_policy_details['backup_start_time']),
            ('retentiondays', self.snapshot_policy_details['retention_days']),
            ('backupunit', self.snapshot_policy_details['backup_unit'])
        )
        updates = []

        for field, existing_value in field_mappings:
            if field == 'backupstarttime':
                updates.append(existing_value != '{0}00'.format(getattr(self, field)))
            else:
                updates.append(existing_value != getattr(self, field))

        return updates

    def delete_snapshot_policy(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'rmsnapshotpolicy'
        cmdargs = [self.name]
        cmdopts = None

        if self.removefromvolumegroups:
            cmdopts = {
                'removefromvolumegroups': True
            }

        self.restapi.svc_run_command(cmd, cmdopts=cmdopts, cmdargs=cmdargs)
        self.log('Snapshot policy (%s) deleted', self.name)
        self.changed = True

    def update_snapshot_scheduler(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'chsystem'
        cmdopts = {'snapshotpolicysuspended': 'yes' if self.state == 'suspend' else 'no'}

        self.restapi.svc_run_command(cmd, cmdopts=cmdopts, cmdargs=None)
        self.log('Snapshot scheduler status changed: %s', self.state)
        self.changed = True

    def apply(self):
        if self.state in ['resume', 'suspend']:
            self.update_snapshot_scheduler()
            self.msg = 'Snapshot scheduler {0}ed'.format(self.state.rstrip('e'))
        else:
            if self.policy_exists():
                if self.state == 'present':
                    modifications = self.snapshot_policy_probe()
                    if any(modifications):
                        self.msg = 'Policy modification is not supported in ansible. Please delete and recreate new policy.'
                    else:
                        self.msg = 'Snapshot policy ({0}) already exists. No modifications done.'.format(self.name)
                else:
                    self.delete_snapshot_policy()
                    self.msg = 'Snapshot policy ({0}) deleted.'.format(self.name)
            else:
                if self.state == 'absent':
                    self.msg = 'Snapshot policy ({0}) does not exist. No modifications done.'.format(self.name)
                else:
                    self.create_snapshot_policy()
                    self.msg = 'Snapshot policy ({0}) created.'.format(self.name)

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'

        self.module.exit_json(
            changed=self.changed,
            msg=self.msg
        )


def main():
    v = IBMSVCSnapshotPolicy()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
