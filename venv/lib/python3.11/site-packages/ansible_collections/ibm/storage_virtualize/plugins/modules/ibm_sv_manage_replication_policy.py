#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2022 IBM CORPORATION
# Author(s): Sanjaikumaar M <sanjaikumaar.m@ibm.com>
#            Sandip Gulab Rajbanshi <sandip.rajbanshi@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_sv_manage_replication_policy
short_description: This module configures and manages replication policies on IBM Storage Virtualize family systems
version_added: '1.10.0'
description:
  - Ansible interface to manage mkreplicationpolicy, chreplicationpolicy, and rmreplicationpolicy commands.
  - This module manages policy based replication.
  - This module can be run on all IBM Storage Virtualize systems with version 8.5.2.1 or later.
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
            - Creates, updates (C(present)), or deletes (C(absent)) a replication policy.
        choices: [ present, absent ]
        required: true
        type: str
    name:
        description:
            - Specifies the name of the replication policy.
        type: str
        required: true
    topology:
        description:
            - Specifies the policy topology.
        choices: [ 2-site-async-dr, 2-site-ha, async-dr ]
        type: str
    location1system:
        description:
            - Specifies the name or ID of the system in location 1 of the topology.
        type: str
    location1iogrp:
        description:
            - Specifies the ID of the I/O group of the system in location 1 of the topology.
        type: int
    location2system:
        description:
            - Specifies the name or ID of the system in location 2 of the topology.
        type: str
    location2iogrp:
        description:
            - Specifies the ID of the I/O group of the system in location 2 of the topology.
        type: int
    rpoalert:
        description:
            - Specifies the RPO alert threshold in seconds.
              The minimum value is 60 (1 minute) and the maximum value is 86400 (1 day).
            - The value must be a multiple of 60 seconds.
        type: int
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
    partition:
        description:
            - Specifies the name of the storage partition to be assigned to async-dr replication policy.
            - Applies when I(state=present).
            - Supported from Storage Virtualize family systems 8.7.1.0 or later.
        type: str
        version_added: 2.6.0
    ha_snapshots:
        description:
            - When specified as I(yes), snapshots created for volumes and volume groups associated with the policy will be replicated to the remote system.
            - Applies when I(state=present) and I(topology=2-site-ha).
            - Supported from Storage Virtualize family systems 8.7.3.0 or later.
        type: str
        choices: ['yes', 'no']
        version_added: 2.7.0
author:
    - Sanjaikumaar M (@sanjaikumaar)
    - Sandip Gulab Rajbanshi (@Sandip-Rajbanshi)
notes:
    - This module supports C(check_mode).
    - If both systems support HA snapshots, ha_snapshots will be enabled implicitly while creating replication policy with topology "2-site-ha".
    - Error Considerations
        - CMMVC1255E The command failed because the specified topology does not support highly-available snapshots
'''

EXAMPLES = '''
- name: Create replication policy
  ibm.storage_virtualize.ibm_sv_manage_replication_policy:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: replication_policy0
    topology: 2-site-async-dr
    location1system: x.x.x.x
    location1iogrp: 0
    location2system: x.x.x.x
    location2iogrp: 0
    rpoalert: 60
    state: present
- name: Delete replication policy
  ibm.storage_virtualize.ibm_sv_manage_replication_policy:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: replication_policy0
    state: absent
- name: Create DR replication policy
  ibm.storage_virtualize.ibm_sv_manage_replication_policy:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: replication_policy0
    topology: async-dr
    partition: partition0
    rpoalert: 60
    state: present
- name: Create replication policy with HA snapshots enabled
  ibm.storage_virtualize.ibm_sv_manage_replication_policy:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: replication_policy0
    topology: 2-site-ha
    location1system: x.x.x.x
    location1iogrp: 0
    location2system: x.x.x.x
    location2iogrp: 0
    state: present
    ha_snapshots: "yes"
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (
    IBMSVCRestApi, svc_argument_spec,
    get_logger
)
from ansible.module_utils._text import to_native


class IBMSVReplicationPolicy:

    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                name=dict(
                    type='str',
                    required=True
                ),
                state=dict(
                    type='str',
                    choices=['present', 'absent'],
                    required=True
                ),
                topology=dict(
                    type='str',
                    choices=['2-site-async-dr', '2-site-ha', 'async-dr']
                ),
                location1system=dict(
                    type='str',
                ),
                location1iogrp=dict(
                    type='int',
                ),
                location2system=dict(
                    type='str',
                ),
                location2iogrp=dict(
                    type='int',
                ),
                rpoalert=dict(
                    type='int',
                ),
                partition=dict(
                    type='str',
                ),
                ha_snapshots=dict(
                    type='str',
                    choices=['yes', 'no']
                )
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # Required parameters
        self.name = self.module.params['name']
        self.state = self.module.params['state']

        # Optional parameters
        self.topology = self.module.params.get('topology', '')
        self.location1system = self.module.params.get('location1system', '')
        self.location1iogrp = self.module.params.get('location1iogrp', '')
        self.location2system = self.module.params.get('location2system', '')
        self.location2iogrp = self.module.params.get('location2iogrp', '')
        self.rpoalert = self.module.params.get('rpoalert', '')
        self.partition = self.module.params.get('partition', '')
        self.ha_snapshots = self.module.params.get('ha_snapshots', '')

        # logging setup
        self.log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, self.log_path)
        self.log = log.info

        self.basic_checks()

        # Dynamic variables
        self.changed = False
        self.msg = ''
        self.rp_data = {}

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
        if not self.name:
            self.module.fail_json(
                msg='Missing mandatory parameter: name'
            )

        if self.state == 'absent':
            invalids = ('topology', 'location1system', 'location1iogrp', 'location2system', 'location2iogrp', 'rpoalert',
                        'partition', 'ha_snapshots')
            invalid_exists = ', '.join((var for var in invalids if not getattr(self, var) in {'', None}))

            if invalid_exists:
                self.module.fail_json(
                    msg='state=absent but following parameters have been passed: {0}'.format(invalid_exists)
                )
        if (self.topology == "async-dr" and not self.partition) or (self.topology != "async-dr" and self.partition):
            self.module.fail_json(msg="DR policy async-dr and partition name must be used together to create a async-dr replication policy!!")
        if self.topology == "async-dr":
            invalids = ('location1system', 'location1iogrp', 'location2system', 'location2iogrp')
            invalid_exists = ', '.join((var for var in invalids if not getattr(self, var) in {'', None}))

            if invalid_exists:
                self.module.fail_json(
                    msg="For topology 'async-dr' these parameters are invalid {0}".format(invalid_exists)
                )
        if self.ha_snapshots and getattr(self, "topology", None) != "2-site-ha":
            self.module.fail_json(
                msg="CMMVC1255E The command failed because the specified topology does not support highly-available snapshots"
            )

    def is_replication_policy_present(self):
        result = {}
        cmd = 'lsreplicationpolicy'
        data = self.restapi.svc_obj_info(cmd=cmd, cmdopts=None, cmdargs=[self.name])

        if isinstance(data, list):
            for d in data:
                result.update(d)
        else:
            result = data

        self.rp_data = result

        return result

    def create_replication_policy(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'mkreplicationpolicy'
        cmdopts = {
            'name': self.name,
            'topology': self.topology,
            'location1system': self.location1system,
            'location1iogrp': self.location1iogrp,
            'location2system': self.location2system,
            'location2iogrp': self.location2iogrp,
            'rpoalert': self.rpoalert,
            'partition': self.partition,
            'snapshots': self.ha_snapshots
        }

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log('Replication policy (%s) created', self.name)
        self.changed = True

    def delete_replication_policy(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'rmreplicationpolicy'
        self.restapi.svc_run_command(cmd, cmdopts=None, cmdargs=[self.name])
        self.log('Replication policy (%s) deleted', self.name)
        self.changed = True

    def replication_policy_probe(self, data):
        # Mapping the parameters with the existing data for comparision
        params_mapping = (
            ('topology', data.get('topology')),
            ('partition', data.get('partition_name')),
            ('location1iogrp', data.get('location1_iogrp_id')),
            ('location2iogrp', data.get('location2_iogrp_id')),
            ('ha_snapshots', data.get('snapshots'))
        )
        props = dict((k, getattr(self, k)) for k, v in params_mapping if getattr(self, k) and getattr(self, k) != v)
        if self.rpoalert and self.rpoalert != int(data.get('rpo_alert')):
            props["rpoalert"] = self.rpoalert
        if self.location1system and self.location1system != data.get('location1_system_name') and self.location1system != data.get('location1_system_id'):
            props['location1system'] = self.location1system
        if self.location2system and self.location2system != data.get('location2_system_name') and self.location2system != data.get('location2_system_id'):
            props['location1system'] = self.location1system
        self.log("Replication policy modification data: %s", props)
        return props

    def apply(self):
        data = self.is_replication_policy_present()
        if data:
            if self.state == 'present':
                if self.replication_policy_probe(data):
                    self.module.fail_json(msg='Replication policy ({0}) already exists, modification cannot be done'.format(self.name))
                else:
                    self.msg = 'Replication policy ({0}) already exists.'.format(self.name)
            else:
                self.delete_replication_policy()
                self.msg = 'Replication policy ({0}) deleted'.format(self.name)
        else:
            if self.state == 'absent':
                self.msg = 'Replication policy ({0}) does not exists.'.format(self.name)
            else:
                self.create_replication_policy()
                self.msg = 'Replication policy ({0}) created.'.format(self.name)

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'

        self.module.exit_json(
            changed=self.changed,
            msg=self.msg
        )


def main():
    v = IBMSVReplicationPolicy()
    try:
        v.apply()
    except Exception as e:
        v.log('Exception in apply(): \n%s', format_exc())
        v.module.fail_json(msg='Module failed. Error [%s].' % to_native(e))


if __name__ == '__main__':
    main()
