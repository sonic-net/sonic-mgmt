#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 IBM CORPORATION
# Author(s): Shilpi Jain <shilpi.jain1@ibm.com>
#            Sanjaikumaar M <sanjaikumaar.m@ibm.com>
#            Sumit Kumar Gupta <sumit.gupta16@ibm.com>
#            Sandip Gulab Rajbanshi <sandip.rajbanshi@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_manage_volumegroup
short_description: This module manages volume groups on IBM Storage Virtualize family systems
version_added: "1.6.0"
description:
  - Ansible interface to manage 'mkvolumegroup', 'chvolumegroup', and 'rmvolumegroup'
    commands.
options:
    name:
        description:
            - Specifies the name for the volume group.
        required: true
        type: str
    state:
        description:
            - Creates or updates (C(present)) or removes (C(absent)) a volume group.
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
    log_path:
        description:
            - Path of debug log file.
        type: str
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
    ownershipgroup:
        description:
            - Specifies the name of the ownership group to which the object is being added.
            - I(ownershipgroup) is mutually exclusive with parameters I(safeguardpolicyname) and I(noownershipgroup).
            - Applies when I(state=present).
        type: str
    noownershipgroup:
        description:
            - If specified `True`, the object is removed from the ownership group to which it belongs.
            - Parameters I(ownershipgroup) and I(noownershipgroup) are mutually exclusive.
            - Applies when I(state=present) to modify an existing volume group.
        type: bool
    safeguardpolicyname:
        description:
            - The name of the Safeguarded policy to be assigned to the volume group.
            - I(safeguardpolicyname) is mutually exclusive with parameters I(nosafeguardpolicy) and I(ownershipgroup).
            - Applies when I(state=present).
        type: str
    nosafeguardpolicy:
        description:
            - If specified `True`, removes the Safeguarded policy assigned to the volume group.
            - Parameters I(safeguardpolicyname) and I(nosafeguardpolicy) are mutually exclusive.
            - Applies when I(state=present) to modify an existing volume group.
        type: bool
    snapshotpolicy:
        description:
            - The name of the snapshot policy to be assigned to the volume group.
            - I(snapshotpolicy) is mutually exclusive with parameters I(nosnapshotpolicy) and I(ownershipgroup).
            - Applies when I(state=present).
        type: str
        version_added: 1.9.0
    nosnapshotpolicy:
        description:
            - If specified `True`, removes the snapshot policy assigned to the volume group.
            - Parameters I(snapshotpolicy) and I(nosnapshotpolicy) are mutually exclusive.
            - Applies when I(state=present) to modify an existing volume group.
        type: bool
        version_added: 1.9.0
    snapshotpolicysuspended:
        description:
            - Specifies whether to suspend (C(yes)) or resume (C(no)) the snapshot policy on this volume group.
            - Applies when I(state=present) to modify an existing volume group.
        choices: [ 'yes', 'no' ]
        type: str
        version_added: 1.9.0
    policystarttime:
        description:
            - Specifies the time when the first Safeguarded backup is to be taken.
            - This parameter can also be associated with snapshot policy.
            - I(safeguardpolicyname) is required when using I(policystarttime).
            - The accepted format is YYMMDDHHMM.
            - Applies when I(state=present).
        type: str
    type:
        description:
            - Specifies the type of volume group to be created from the snapshot.
            - Valid during creation of host accessible volume group from an existing snapshot.
            - Also used to convert a thinclone volumegroup to clone. type = clone should be specified.
        choices: [ clone, thinclone ]
        type: str
        version_added: 1.9.0
    snapshot:
        description:
            - Specifies the name of the snapshot used to prepopulate the new volumes in the new volume group.
            - Required when creating a host accessible volume group from an existing snapshot.
        type: str
        version_added: 1.9.0
    fromsourcegroup:
        description:
            - Specifies the parent volume group of the snapshot. This is used to prepopulate the new volume in the
              new volume group.
            - Valid during creation of host accessible volume group from an existing snapshot.
        type: str
        version_added: 1.9.0
    pool:
        description:
            - Specifies the pool name where the target volumes are to be created.
            - Valid during creation of host accessible volume group from an existing snapshot.
        type: str
        version_added: 1.9.0
    iogrp:
        description:
            - Specifies the I/O group for new volumes.
            - Valid during creation of host accessible volume group from an existing snapshot.
        type: str
        version_added: 1.9.0
    safeguarded:
        description:
            - If specified, the snapshot policy creates safeguarded snapshots.
            - Should be specified along with I(snapshotpolicy).
            - Valid during creation and update of a volume group.
            - Supported from Storage Virtualize family systems 8.5.2.0 or later.
        default: false
        type: bool
        version_added: 1.10.0
    ignoreuserfcmaps:
        description:
            - Allows user to create snapshots through the scheduler or manually with `addsnapshot`.
              This can only be used if a volume in the volume group is used as a source of a user legacy
              FlashCopy mapping.
            - Valid during creation and update of a volume group.
            - Supported from Storage Virtualize family systems 8.5.2.0 or later.
        choices: [ 'yes', 'no' ]
        type: str
        version_added: 1.10.0
    replicationpolicy:
        description:
            - Specifies the name of the replication policy to be assigned to the volume group.
            - Applies when I(state=present).
            - Supported from Storage Virtualize family systems 8.5.2.1 or later.
        type: str
        version_added: 1.10.0
    noreplicationpolicy:
        description:
            - If specified `True`, removes the replication policy assigned to the volume group.
            - I(noreplicationpolicy) is mutually exclusive with parameters I(replicationpolicy) and I(nodrreplication).
            - Applies when I(state=present) to modify an existing volume group.
            - Supported from Storage Virtualize family systems 8.5.2.1 or later.
        type: bool
        version_added: 1.10.0
    old_name:
        description:
            - Specifies the old name of the volume group during renaming.
            - Valid when I(state=present), to rename an existing volume group.
        type: str
        version_added: '2.0.0'
    partition:
        description:
            - Specifies the name of the storage partition to be assigned to the volume group.
            - Applies when I(state=present).
            - Supported from Storage Virtualize family systems 8.6.1.0 or later.
        type: str
        version_added: 2.1.0
    evictvolumes:
        description:
            - If specified `True`, delete the volume group but does not remove volumes.
            - Applies when I(state=absent) to delete the volume group, keeping associated volumes.
            - Supported from Storage Virtualize family systems from 8.6.2.0 or later.
        type: bool
        version_added: 2.2.0
    fromsourcevolumes:
        description:
            - Specifies colon-separated list of the parent volumes.
            - When combined with the type parameter and a snapshot, this allows the user to create a volumegroup with a
              subset of those volumes whose image is present in a snapshot.
            - Applies when I(state=present) to create volumegroup clone or thinclone, from subset of volumes of snapshot.
            - Supported from Storage Virtualize family systems from 8.6.2.0 or later.
        type: str
        version_added: 2.3.0
    draftpartition:
        description:
            - Specifies the name of the draft partition to be assigned to the volume group.
            - Applies when I(state=present).
            - Supported from Storage Virtualize family systems 8.6.3.0 or later.
        type: str
        version_added: 2.5.0
    nodrreplication:
        description:
            - If specified `True`, removes the volume group from the async-dr replication policy.
            - I(nodrreplication) is mutually exclusive with parameters I(replicationpolicy) and I(noreplicationpolicy).
            - Applies when I(state=present) to modify an existing volume group.
            - Supported from Storage Virtualize family systems 8.7.1.0 or later.
        type: bool
        version_added: 2.6.0

author:
    - Shilpi Jain(@Shilpi-J)
    - Sanjaikumaar M (@sanjaikumaar)
    - Sumit Kumar Gupta (@sumitguptaibm)
    - Sandip G. Rajbanshi (@Sandip-Rajbanshi)
notes:
    - This module supports C(check_mode).
    - Safeguarded policy and snapshot policy cannot be used at the same time.
      Therefore, the parameters I(snapshotpolicy) and I(safeguardpolicyname) are mutually exclusive.
'''

EXAMPLES = '''
- name: Create a new volume group
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: vg0
    state: present
- name: Delete a volume group
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: vg0
    state: absent
- name: Update existing volume group to remove ownershipgroup and attach a safeguardpolicy to it
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: vg0
    state: present
    noownershipgroup: true
    safeguardpolicyname: sg1
- name: Update volumegroup with snapshot policy and remove safeguarded policy
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: vg0
    nosafeguardpolicy: true
    snapshotpolicy: sp1
    state: present
- name: Update volumegroup with safeguarded snapshot policy and ignoreuserfcmaps
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: vg0
    safeguarded: true
    snapshotpolicy: sp1
    ignoreuserfcmaps: 'yes'
    state: present
- name: Suspend snapshot policy in an existing volume group
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: vg0
    snapshotpolicysuspended: true
    state: present
- name: Create host accessible volume group from an existing snapshot
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: host_accessible_vg
    type: clone
    snapshot: snapshot0
    fromsourcegroup: vg0
    pool: Pool0
    state: present
- name: Create a volumegroup thinclone from a list of volumes
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: vg0
    type: thinclone
    fromsourcevolumes: vol1:vol2
    pool: Pool0
    state: present
- name: Create a volumegroup clone from a list of volumes
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: vg0
    type: clone
    fromsourcevolumes: vol1:vol2
    pool: Pool0
    state: present
- name: Convert a thinclone volumegroup to clone
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: vg0
    type: clone
    state: present
- name: Delete a volume group, keeping volumes which were associated with volumegroup
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: vg0
    state: absent
    evictvolumes: true
- name: Add new or existing volumegroup to a draft partition
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: vg0
    state: present
    draftpartition: partition_name
- name: Remove DR replication-policy from volume group
  ibm.storage_virtualize.ibm_svc_manage_volumegroup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: vg0
    state: absent
    nodrreplication: true
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import \
    IBMSVCRestApi, svc_argument_spec, get_logger, strtobool
from ansible.module_utils._text import to_native
import random


class IBMSVCVG(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(type='str', required=True, choices=['absent',
                                                               'present']),
                ownershipgroup=dict(type='str', required=False),
                noownershipgroup=dict(type='bool', required=False),
                safeguardpolicyname=dict(type='str', required=False),
                nosafeguardpolicy=dict(type='bool', required=False),
                policystarttime=dict(type='str', required=False),
                snapshotpolicy=dict(type='str', required=False),
                nosnapshotpolicy=dict(type='bool', required=False),
                snapshotpolicysuspended=dict(type='str', choices=['yes', 'no']),
                type=dict(type='str', choices=['clone', 'thinclone']),
                snapshot=dict(type='str'),
                fromsourcegroup=dict(type='str'),
                fromsourcevolumes=dict(type='str', required=False),
                pool=dict(type='str'),
                iogrp=dict(type='str'),
                safeguarded=dict(type='bool', default=False),
                ignoreuserfcmaps=dict(type='str', choices=['yes', 'no']),
                replicationpolicy=dict(type='str'),
                noreplicationpolicy=dict(type='bool'),
                old_name=dict(type='str', required=False),
                partition=dict(type='str'),
                evictvolumes=dict(type='bool'),
                draftpartition=dict(type='str'),
                nodrreplication=dict(type='bool')
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
        self.ownershipgroup = self.module.params.get('ownershipgroup', '')
        self.noownershipgroup = self.module.params.get('noownershipgroup', False)
        self.policystarttime = self.module.params.get('policystarttime', '')
        self.snapshotpolicy = self.module.params.get('snapshotpolicy', '')
        self.nosnapshotpolicy = self.module.params.get('nosnapshotpolicy', False)
        self.snapshotpolicysuspended = self.module.params.get('snapshotpolicysuspended', '')
        self.type = self.module.params.get('type', '')
        self.snapshot = self.module.params.get('snapshot', '')
        self.fromsourcegroup = self.module.params.get('fromsourcegroup', '')
        self.fromsourcevolumes = self.module.params.get('fromsourcevolumes', '')
        self.pool = self.module.params.get('pool', '')
        self.iogrp = self.module.params.get('iogrp', '')
        self.safeguardpolicyname = self.module.params.get('safeguardpolicyname', '')
        self.nosafeguardpolicy = self.module.params.get('nosafeguardpolicy', False)
        self.safeguarded = self.module.params.get('safeguarded', False)
        self.ignoreuserfcmaps = self.module.params.get('ignoreuserfcmaps', '')
        self.replicationpolicy = self.module.params.get('replicationpolicy', '')
        self.noreplicationpolicy = self.module.params.get('noreplicationpolicy', False)
        self.old_name = self.module.params.get('old_name', '')
        self.partition = self.module.params.get('partition', '')
        self.evictvolumes = self.module.params.get('evictvolumes', False)
        self.draftpartition = self.module.params.get('draftpartition', '')
        self.nodrreplication = self.module.params.get('nodrreplication', False)

        # Dynamic variable
        self.parentuid = None
        self.changed = False
        self.msg = ''

        self.basic_checks()

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
        changed = False
        if not self.name:
            self.module.fail_json(msg='Missing mandatory parameter: name')

        if self.state == 'present':
            if self.policystarttime:
                if not self.snapshotpolicy and not self.safeguardpolicyname:
                    self.module.fail_json(
                        msg='Either `snapshotpolicy` or `safeguardpolicyname` should be passed along with `policystarttime`.'
                    )
            if self.safeguarded:
                if not self.snapshotpolicy:
                    self.module.fail_json(
                        msg='Parameter `safeguarded` should be passed along with `snapshotpolicy`'
                    )
            if self.evictvolumes is not None:
                self.module.fail_json(
                    msg='Parameter `evictvolumes` should be passed only while removing volumegroup'
                )
        elif self.state == 'absent':
            unwanted = ('ownershipgroup', 'noownershipgroup', 'safeguardpolicyname',
                        'nosafeguardpolicy', 'snapshotpolicy', 'nosnapshotpolicy',
                        'policystarttime', 'type', 'fromsourcegroup', 'pool', 'iogrp',
                        'safeguarded', 'ignoreuserfcmaps', 'replicationpolicy',
                        'noreplicationpolicy', 'old_name', 'fromsourcevolumes', 'draftpartition', 'nodrreplication')

            param_exists = ', '.join((param for param in unwanted if getattr(self, param)))

            if param_exists:
                self.module.fail_json(
                    msg='State=absent but following parameter(s) exist: {0}'.format(param_exists),
                    changed=changed
                )
        else:
            self.module.fail_json(msg='State should be either present or absent')

    def parameter_handling_while_renaming(self):
        parameters = {
            "ownershipgroup": self.ownershipgroup,
            "noownershipgroup": self.noownershipgroup,
            "replicationpolicy": self.replicationpolicy,
            "noreplicationpolicy": self.noreplicationpolicy,
            "safeguardpolicyname": self.safeguardpolicyname,
            "nosafeguardpolicy": self.nosafeguardpolicy,
            "snapshotpolicy": self.snapshotpolicy,
            "nosnapshotpolicy": self.nosnapshotpolicy,
            "partition": self.partition,
            "fromsourcevolumes": self.fromsourcevolumes,
            "nodrreplication": self.nodrreplication
        }
        parameters_exists = [parameter for parameter, value in parameters.items() if value]
        if parameters_exists:
            self.module.fail_json(msg="Parameters {0} not supported while renaming a volume group.".format(', '.join(parameters_exists)))

    def create_validation(self):
        mutually_exclusive = (
            ('ownershipgroup', 'safeguardpolicyname'),
            ('ownershipgroup', 'snapshotpolicy'),
            ('ownershipgroup', 'policystarttime'),
            ('snapshotpolicy', 'safeguardpolicyname'),
            ('replicationpolicy', 'noreplicationpolicy'),
            ('draftpartition', 'partition'),
            ('replicationpolicy', 'nodrreplication'),
            ('noreplicationpolicy', 'nodrreplication')
        )

        for param1, param2 in mutually_exclusive:
            if getattr(self, param1) and getattr(self, param2):
                self.module.fail_json(
                    msg='Mutually exclusive parameters: {0}, {1}'.format(param1, param2)
                )

        unsupported = ('nosafeguardpolicy', 'noownershipgroup', 'nosnapshotpolicy',
                       'snapshotpolicysuspended', 'noreplicationpolicy', 'nodrreplication')
        unsupported_exists = ', '.join((field for field in unsupported if getattr(self, field)))

        if unsupported_exists:
            self.module.fail_json(
                msg='Following parameters not supported during creation scenario: {0}'.format(unsupported_exists)
            )

    def update_validation(self, data):
        mutually_exclusive = (
            ('ownershipgroup', 'noownershipgroup'),
            ('safeguardpolicyname', 'nosafeguardpolicy'),
            ('ownershipgroup', 'safeguardpolicyname'),
            ('ownershipgroup', 'snapshotpolicy'),
            ('ownershipgroup', 'policystarttime'),
            ('nosafeguardpolicy', 'nosnapshotpolicy'),
            ('snapshotpolicy', 'nosnapshotpolicy'),
            ('snapshotpolicy', 'safeguardpolicyname'),
            ('replicationpolicy', 'nodrreplication'),
            ('noreplicationpolicy', 'nodrreplication')
        )

        for param1, param2 in mutually_exclusive:
            if getattr(self, param1) and getattr(self, param2):
                self.module.fail_json(
                    msg='Mutually exclusive parameters: {0}, {1}'.format(param1, param2)
                )

        if self.type:
            # converttoclone accepts only type=clone, so update validation will include that
            if self.type == 'clone':
                invalids_while_converting_to_clone = ('safeguardpolicyname', 'nosafeguardpolicy', 'ownershipgroup',
                                                      'snapshotpolicy', 'policystarttime', 'nosnapshotpolicy',
                                                      'replicationpolicy', 'nodrreplication', 'noreplicationpolicy')
                invalid_params_for_convert_to_clone = ', '.join((param for param in invalids_while_converting_to_clone
                                                                if getattr(self, param)))

                if invalid_params_for_convert_to_clone:
                    self.module.fail_json(
                        msg='Following parameter(s) are invalid while converting thinclone volumegroup to clone: {0}'
                        .format(invalid_params_for_convert_to_clone)
                    )
            else:
                # If type=thinclone (or some invalid value) was passed, return error.
                self.module.fail_json(
                    msg='type = {0} is invalid for updating volumegroup. Only type = clone is supported.'
                    .format(self.type)
                )

        unsupported_maps = (
            ('snapshot', data.get('source_snapshot', '')),
            ('fromsourcevolumes', data.get('source_volumes_set', '')),
            ('fromsourcegroup', data.get('source_volume_group_name', '')),
            ('partition', data.get('partition_name', ''))
        )
        unsupported = (
            fields[0] for fields in unsupported_maps if getattr(self, fields[0]) and getattr(self, fields[0]) != fields[1]
        )
        unsupported_exists = ', '.join(unsupported)

        if unsupported_exists:
            self.module.fail_json(
                msg='Following parameters not supported during update: {0}'.format(unsupported_exists)
            )

    def get_existing_vg(self, vg_name):
        merged_result = {}

        data = self.restapi.svc_obj_info(cmd='lsvolumegroup', cmdopts=None,
                                         cmdargs=['-gui', vg_name])

        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        if merged_result and ((self.snapshotpolicy and self.policystarttime) or self.snapshotpolicysuspended):
            # Making new call as snapshot_policy_start_time not available in lsvolumegroup CLI
            SP_data = self.restapi.svc_obj_info(
                cmd='lsvolumegroupsnapshotpolicy',
                cmdopts=None,
                cmdargs=[self.name]
            )
            merged_result['snapshot_policy_start_time'] = SP_data['snapshot_policy_start_time']
            merged_result['snapshot_policy_suspended'] = SP_data['snapshot_policy_suspended']

        # Make new call as volume list is not present in lsvolumegroup CLI
        # If existing volumegroup is a thinclone but command params don't contain
        #  [type], that is also considered as an attempt to create/change an already
        #  existing volume. So, it should be recorded to throw error later.
        is_existing_vg_thinclone = False

        if merged_result and merged_result.get('volume_group_type') == 'thinclone':
            is_existing_vg_thinclone = True
        if merged_result and (self.type and self.fromsourcevolumes) or is_existing_vg_thinclone is True:
            volumes_data = []
            if self.type == "thinclone" or is_existing_vg_thinclone is True:
                cmd = 'lsvolumepopulation'
                cmdopts = {"filtervalue": "volume_group_name={0}".format(self.name)}
                volumes_data = self.restapi.svc_obj_info(cmd, cmdopts, cmdargs=None)
            else:
                # Source volumes for clone volumes needs to be fetched for verification
                # 1. First get the volumes associated with volumegroup provided
                associated_volumes_data = []
                cmd = 'lsvdisk'
                cmdopts = {"filtervalue": "volume_group_name={0}".format(self.name)}
                associated_volumes_data = self.restapi.svc_obj_info(cmd, cmdopts, cmdargs=None)
                vol_names = set()
                for vol in associated_volumes_data:
                    vol_names.add(vol['name'])

                # 2. Run lsvdisk for each volume provided in command to get source_volume_name
                for volname in vol_names:
                    cmd = 'lsvdisk' + "/" + volname
                    cmdopts = None
                    cmdargs = None
                    single_vol_data = self.restapi.svc_obj_info(cmd, cmdopts, cmdargs=None)
                    if single_vol_data:
                        volumes_data.append(single_vol_data[0])

            # Make a set from source volumes of all volumes
            if volumes_data:
                source_volumes_set = set()
                source_volumes_pool_set = set()
                for volume_data in volumes_data:
                    # Add the value of 'source_volume_name' to the merged_result
                    source_volumes_set.add(volume_data['source_volume_name'])
                merged_result['source_volumes_set'] = source_volumes_set
                # If pool is provided, verify that pool matches with the one provided in command
                if self.pool:
                    cmd = 'lsvdisk'
                    cmdopts = {"filtervalue": "parent_mdisk_grp_name={0}".format(self.pool)}

                    vdisks_data = self.restapi.svc_obj_info(cmd, cmdopts, cmdargs=None)
                    remaining_vdisks = len(source_volumes_set)
                    for vdisk_data in vdisks_data:
                        if vdisk_data['name'] in source_volumes_set:
                            source_volumes_pool_set.add(vdisk_data['parent_mdisk_grp_name'])
                            remaining_vdisks = remaining_vdisks - 1
                            if remaining_vdisks == 0:
                                break

                merged_result['source_volumes_pool_set'] = source_volumes_pool_set

        return merged_result

    def set_parentuid(self):
        if self.snapshot and not self.fromsourcegroup:
            cmdopts = {
                "filtervalue": "snapshot_name={0}".format(self.snapshot)
            }
            data = self.restapi.svc_obj_info(
                cmd='lsvolumesnapshot',
                cmdopts=cmdopts,
                cmdargs=None
            )
            try:
                result = next(
                    filter(
                        lambda obj: obj['volume_group_name'] == '',
                        data
                    )
                )
            except StopIteration:
                self.module.fail_json(
                    msg='Orphan Snapshot ({0}) does not exists for the given name'.format(self.snapshot)
                )
            else:
                self.parentuid = result['parent_uid']

    def vg_probe(self, data):
        self.update_validation(data)
        # Mapping the parameters with the existing data for comparision
        params_mapping = (
            ('ownershipgroup', data.get('owner_name', '')),
            ('ignoreuserfcmaps', data.get('ignore_user_flash_copy_maps', '')),
            ('replicationpolicy', data.get('replication_policy_name', '')),
            ('noownershipgroup', not bool(data.get('owner_name', ''))),
            ('nosafeguardpolicy', not bool(data.get('safeguarded_policy_name', ''))),
            ('nosnapshotpolicy', not bool(data.get('snapshot_policy_name', ''))),
            ('noreplicationpolicy', not bool(data.get('replication_policy_name', ''))),
            ('partition', data.get('partition_name', '')),
            ('draftpartition', data.get('draft_partition_name', '')),
            ('nodrreplication', not bool(data.get('replication_policy_name', '')))
        )

        props = dict((k, getattr(self, k)) for k, v in params_mapping if getattr(self, k) and getattr(self, k) != v)

        if self.safeguardpolicyname and self.safeguardpolicyname != data.get('safeguarded_policy_name', ''):
            props['safeguardedpolicy'] = self.safeguardpolicyname
            # If policy is changed, existing policystarttime will be erased so adding time without any check
            if self.policystarttime:
                props['policystarttime'] = self.policystarttime
        elif self.safeguardpolicyname:
            if self.policystarttime and self.policystarttime + '00' != data.get('safeguarded_policy_start_time', ''):
                props['safeguardedpolicy'] = self.safeguardpolicyname
                props['policystarttime'] = self.policystarttime
        elif self.snapshotpolicy and self.snapshotpolicy != data.get('snapshot_policy_name', ''):
            props['snapshotpolicy'] = self.snapshotpolicy
            props['safeguarded'] = self.safeguarded
            if self.policystarttime:
                props['policystarttime'] = self.policystarttime
        elif self.snapshotpolicy:
            if self.policystarttime and self.policystarttime + '00' != data.get('snapshot_policy_start_time', ''):
                props['snapshotpolicy'] = self.snapshotpolicy
                props['policystarttime'] = self.policystarttime
            if self.safeguarded not in ('', None) and self.safeguarded != strtobool(data.get('snapshot_policy_safeguarded', 0)):
                props['snapshotpolicy'] = self.snapshotpolicy
                props['safeguarded'] = self.safeguarded

        if self.draftpartition:
            if "draftpartition" in props and props["draftpartition"] == data.get('partition_name'):
                props.pop("draftpartition")
                self.log("Partition [%s] which contains Volumegroup [%s] is already published.", self.draftpartition, self.name)
            elif self.draftpartition == data.get("draft_partition_name"):
                self.log("Partition [%s] which contains Volumegroup [%s] is already in draft state.", self.draftpartition, self.name)

        # Adding snapshotpolicysuspended to props
        if self.snapshotpolicysuspended and self.snapshotpolicysuspended != data.get('snapshot_policy_suspended', ''):
            props['snapshotpolicysuspended'] = self.snapshotpolicysuspended

        if self.type and self.type != data.get('volume_group_type'):
            # Handle cases other than '' to clone
            if not (data.get('volume_group_type') == '' and self.type == 'clone'):
                props['type'] = self.type

        self.log("volumegroup props = %s", props)

        return props

    def create_transient_snapshot(self):
        # Required parameters
        snapshot_cmd = 'addsnapshot'
        snapshot_opts = {}
        random_number = ''.join(random.choices('0123456789', k=10))
        snapshot_name = f"snapshot_{random_number}"
        snapshot_opts['name'] = snapshot_name

        # Optional parameters
        snapshot_opts['pool'] = self.module.params.get('pool', '')
        snapshot_opts['volumes'] = self.module.params.get('fromsourcevolumes', '')
        snapshot_opts['retentionminutes'] = 5

        self.restapi.svc_run_command(snapshot_cmd, snapshot_opts, cmdargs=None, timeout=10)
        return snapshot_name

    def vg_create(self):
        self.create_validation()
        if self.module.check_mode:
            self.changed = True
            return

        self.log("creating volume group '%s'", self.name)

        # Make command
        cmd = 'mkvolumegroup'
        cmdopts = {
            'name': self.name,
            'safeguarded': self.safeguarded
        }

        if self.type:
            optional_params = ('type', 'snapshot', 'pool')
            cmdopts.update(
                dict(
                    (param, getattr(self, param)) for param in optional_params if getattr(self, param)
                )
            )
            if self.iogrp:
                cmdopts['iogroup'] = self.iogrp

            if self.fromsourcevolumes:
                cmdopts['fromsourcevolumes'] = self.fromsourcevolumes
                if not self.snapshot:
                    # If thinclone or clone is to be created from volumes, do following:
                    # 1. Create transient snapshot with 5-min retentionminutes
                    # 2. Create a thinclone volumegroup from this snapshot
                    # 3. There is no need to delete snapshot, as it is auto-managed due to retentionminutes
                    try:
                        self.snapshot = self.create_transient_snapshot()
                        cmdopts['snapshot'] = self.snapshot
                    except Exception as e:
                        self.log('Exception in creating transient snapshot: %s', format_exc())
                        self.module.fail_json(msg='Module failed. Error [%s].' % to_native(e))
            self.set_parentuid()
            if self.parentuid:
                cmdopts['fromsourceuid'] = self.parentuid
            elif self.fromsourcegroup:
                cmdopts['fromsourcegroup'] = self.fromsourcegroup

        if self.ignoreuserfcmaps:
            if self.ignoreuserfcmaps == 'yes':
                cmdopts['ignoreuserfcmaps'] = True
            else:
                cmdopts['ignoreuserfcmaps'] = False

        if self.replicationpolicy:
            cmdopts['replicationpolicy'] = self.replicationpolicy

        if self.partition:
            cmdopts['partition'] = self.partition
        elif self.draftpartition:
            cmdopts['draftpartition'] = self.draftpartition
        if self.ownershipgroup:
            cmdopts['ownershipgroup'] = self.ownershipgroup
        elif self.safeguardpolicyname:
            cmdopts['safeguardedpolicy'] = self.safeguardpolicyname
            if self.policystarttime:
                cmdopts['policystarttime'] = self.policystarttime
        elif self.snapshotpolicy:
            cmdopts['snapshotpolicy'] = self.snapshotpolicy
            if self.policystarttime:
                cmdopts['policystarttime'] = self.policystarttime

        self.log("creating volumegroup '%s'", cmdopts)

        # Run command
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log("create volume group result %s", result)
        # Any error would have been raised in svc_run_command
        self.changed = True

    def vg_update(self, modify):
        if 'type' in modify and modify['type'] != "clone":
            self.module.fail_json(msg='Only type=clone is supported for updating volumegroup.')
        if self.module.check_mode:
            self.changed = True
            return

        # update the volume group
        self.log("updating volume group '%s' ", self.name)
        cmdopts = dict()
        cmdargs = [self.name]

        try:
            del modify['snapshotpolicysuspended']
        except KeyError:
            self.log("snapshotpolicysuspended modification not required!!")
        else:
            cmd = 'chvolumegroupsnapshotpolicy'
            cmdopts = {'snapshotpolicysuspended': self.snapshotpolicysuspended}
            self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        if modify.get('type') == "clone":
            # Run converttoclone command
            cmd = 'converttoclone'
            cmdopts['volumegroup'] = self.name
            cmdargs = None
            self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
            self.log("Volumegroup %s converted from thinclone to clone!!", self.name)
        else:
            cmd = 'chvolumegroup'
            unmaps = ('noownershipgroup', 'nosafeguardpolicy', 'nosnapshotpolicy', 'noreplicationpolicy', 'nodrreplication')
            for field in unmaps:
                cmdopts = {}
                if field == 'nosafeguardpolicy' and field in modify:
                    cmdopts['nosafeguardedpolicy'] = modify.pop('nosafeguardpolicy')
                    self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
                elif field in modify:
                    cmdopts[field] = modify.pop(field)
                    self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

            if modify:
                cmdopts = modify
                self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error would have been raised in svc_run_command
        self.changed = True

    def vg_delete(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("deleting volume group '%s'", self.name)

        cmd = 'rmvolumegroup'
        cmdopts = {}
        cmdargs = [self.name]
        if self.evictvolumes is not None:
            cmdopts['evictvolumes'] = self.evictvolumes

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
        # Any error will have been raised in svc_run_command
        self.changed = True

    def vg_rename(self, vg_data):
        msg = ''
        self.parameter_handling_while_renaming()
        old_vg_data = self.get_existing_vg(self.old_name)

        if not old_vg_data and not vg_data:
            self.module.fail_json(msg="Volume group with old name {0} doesn't exist.".format(self.old_name))
        elif old_vg_data and vg_data:
            self.module.fail_json(msg="Volume group [{0}] already exists.".format(self.name))
        elif not old_vg_data and vg_data:
            msg = "Volume group with name [{0}] already exists.".format(self.name)
        elif old_vg_data and not vg_data:
            # when check_mode is enabled
            if self.module.check_mode:
                self.changed = True
                return
            self.restapi.svc_run_command('chvolumegroup', {'name': self.name}, [self.old_name])
            self.changed = True
            msg = "Volume group [{0}] has been successfully rename to [{1}].".format(self.old_name, self.name)
        return msg

    def apply(self):
        vg_data = self.get_existing_vg(self.name)

        if self.state == 'present' and self.old_name:
            self.msg = self.vg_rename(vg_data)
        elif self.state == 'absent' and self.old_name:
            self.module.fail_json(msg="Rename functionality is not supported when 'state' is absent.")
        else:
            if vg_data:
                if self.state == 'present':
                    is_existing_vg_thinclone = False
                    existing_vg_type = vg_data.get('volume_group_type')
                    if existing_vg_type == 'thinclone':
                        is_existing_vg_thinclone = True

                    if self.type and not self.fromsourcevolumes:
                        modify = self.vg_probe(vg_data)
                        if modify:
                            self.vg_update(modify)
                            self.msg = "Volume group [%s] has been modified." % self.name
                        else:
                            self.msg = "No Modifications detected."
                    else:
                        if (self.type and self.fromsourcevolumes) or is_existing_vg_thinclone is True:
                            # Check whether provided source volumes are same as in existing volumegroup
                            volumes_with_existing_vg = None
                            if 'source_volumes_set' in vg_data:
                                volumes_with_existing_vg = vg_data['source_volumes_set']
                            provided_volumes_set = set()
                            if self.fromsourcevolumes:
                                provided_volumes_set = set(self.fromsourcevolumes.split(":"))
                            if volumes_with_existing_vg or provided_volumes_set:
                                self.changed = False
                                if not provided_volumes_set and volumes_with_existing_vg:
                                    self.module.fail_json(
                                        msg="Existing thinclone volumegroup found.",
                                        changed=self.changed
                                    )
                                if volumes_with_existing_vg != provided_volumes_set:
                                    self.module.fail_json(
                                        msg="Parameter [fromsourcevolumes] is invalid for modifying volumegroup.",
                                        changed=self.changed
                                    )
                                elif self.pool and vg_data['source_volumes_pool_set'] and (list(vg_data['source_volumes_pool_set'])[0] != self.pool):
                                    self.module.fail_json(
                                        msg="Parameter [pool] is invalid for modifying volumegroup.",
                                        changed=self.changed
                                    )
                                else:
                                    self.msg = "A volumegroup with name [%s] already exists." % self.name
                        else:
                            modify = self.vg_probe(vg_data)
                            if modify:
                                self.vg_update(modify)
                                self.msg = "Volume group [%s] has been modified." % self.name
                            else:
                                self.msg = "No Modifications detected, Volume group already exists."
                else:
                    self.vg_delete()
                    self.msg = "Volume group [%s] has been deleted." % self.name
            else:
                if self.state == 'absent':
                    self.msg = "Volume group [%s] does not exist." % self.name
                else:
                    self.vg_create()
                    self.msg = "Volume group [%s] has been created." % self.name

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'

        self.module.exit_json(msg=self.msg, changed=self.changed)


def main():
    v = IBMSVCVG()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
