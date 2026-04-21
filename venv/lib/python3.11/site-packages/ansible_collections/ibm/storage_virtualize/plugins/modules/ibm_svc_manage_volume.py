#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 IBM CORPORATION
# Author(s): Sreshtant Bohidar <sreshtant.bohidar@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ibm_svc_manage_volume
short_description: This module manages standard volumes on IBM Storage Virtualize family systems
description:
  - Ansible interface to manage 'mkvolume', 'rmvolume', and 'chvdisk' volume commands.
version_added: "1.6.0"
options:
  name:
    description:
      - Specifies the name to assign to the new volume.
    required: true
    type: str
  state:
    description:
      - Creates or updates (C(present)) or removes (C(absent)) a volume.
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
      - To generate a token, use the ibm_svc_auth module.
    type: str
  pool:
    description:
      - Specifies the name of the storage pool to use while creating the volume.
      - This parameter is required when I(state=present), to create a volume.
    type: str
  size:
    description:
      - Defines the size of the volume. This parameter can also be used to resize an existing volume.
      - Required when I(state=present), to create or modify a volume.
    type: str
  warning:
    description:
      - Raises a warning when the used disk capacity on the thin-provisioned copy first exceeds the specified threshold.
      - The value is specified as a percentage of the total capacity of the thin-provisioned volume, hence it must be between 0 and 100.
      - When not specified, the default value is 80%.
      - Valid when I(state=present), to create or modify a thin-provisioned or compressed volume.
    type: int
    version_added: '2.7.0'
  unit:
    description:
      - Specifies the data units to use with the capacity that is specified by the 'size' parameter.
      - I(size) is required when using I(unit).
    type: str
    choices: [ b, kb, mb, gb, tb, pb ]
    default: mb
  iogrp:
    description:
      - Specifies the list of I/O group names. Group names in the list must be separated by using a comma.
      - While creating a new volume, the first I/O group in the list is added as both cached & access I/O group,
        while remaining I/O groups are added as access I/O groups.
      - This parameter supports update functionality.
      - Valid when I(state=present), to create or modify a volume.
    type: str
  thin:
    description:
      - Specifies that a thin-provisioned volume is to be created.
      - Parameters 'thin' and 'compressed' are mutually exclusive.
      - Valid when I(state=present), to create a thin-provisioned volume.
    type: bool
  type:
    description:
      - Specifies the type of volume to create. Volume can be thinclone or clone type.
      - Valid when I(state=present), to create a thinclone or clone volume.
      - Supported from Storage Virtualize family systems from 8.6.2.0 or later.
      - Also used to convert a thinclone volume to clone. type = clone should be specified.
    choices: [thinclone, clone]
    type: str
  fromsourcevolume:
    description:
      - Specifies the volume name in the snapshot used to pre-populate clone or thinclone volume.
      - Valid when I(state=present), to create a thinclone or clone volume.
      - Supported from Storage Virtualize family systems from 8.6.2.0 or later.
    type: str
  compressed:
    description:
      - Specifies that a compressed volume is to be created.
      - Parameters 'compressed' and 'thin' are mutually exclusive.
      - Valid when I(state=present), to create a compressed volume.
    type: bool
  buffersize:
    description:
      - Specifies the pool capacity that the volume will reserve as a buffer for thin-provisioned and compressed volumes.
      - Parameter 'thin' or 'compressed' must be specified to use this parameter.
      - The default buffer size is 2%.
      - I(thin) or I(compressed) is required when using I(buffersize).
      - Valid when I(state=present), to create a volume.
    type: str
  deduplicated:
    description:
      - Specifies that a deduplicated volume is to be created.
      - Required when I(state=present), to create a deduplicated volume.
    type: bool
  volumegroup:
    description:
      - Specifies the name of the volumegroup to which the volume is to be added.
      - Parameters 'volumegroup' and 'novolumegroup' are mutually exclusive.
      - Valid when I(state=present), to create or modify a volume.
    type: str
  novolumegroup:
    description:
      - If specified `True`, the volume is removed from its associated volumegroup.
      - Parameters 'novolumegroup' and 'volumegroup' are mutually exclusive.
      - Valid when I(state=present), to modify a volume.
    type: bool
  unmap:
    description:
      - Removes specified objects associated with the volume which is to be deleted.
      - Valid when I(state=absent), to delete a volume.
    type: list
    elements: str
    choices: [ host_mappings, remotecopy_relationships, flashcopy_mappings ]
    version_added: 2.7.0
  old_name:
    description:
      - Specifies the old name of the volume during renaming.
      - Valid when I(state=present), to rename an existing volume.
    type: str
    version_added: '1.9.0'
  enable_cloud_snapshot:
    description:
      - Specify to enable or disable cloud snapshot.
      - Valid when I(state=present), to modify an existing volume.
    type: bool
    version_added: '1.11.0'
  cloud_account_name:
    description:
      - Specifies the name of the cloud account name.
      - Valid when I(enable_cloud_snapshot=true).
    type: str
    version_added: '1.11.0'
  allow_hs:
    description:
      - If specified `True`, manages the hyperswap volume by ignoring the volume type validation.
      - Valid when I(state=present), to modify an existing volume.
    type: bool
    default: false
    version_added: '2.0.0'
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
    - For unmap parameter, the option remotecopy_relationships has been deprecated from 8.7.1.0 onwards.
    - CMMVC9855E The command failed because one of more of the specified volumes does not exist.
      This error occurs when the user-provided volume(s) do not exist.
'''

EXAMPLES = r'''
- name: Create a volume
  ibm.storage_virtualize.ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: "{{ log_path }}"
    name: "volume_name"
    state: "present"
    pool: "pool_name"
    size: "1"
    unit: "gb"
    iogrp: "io_grp0, io_grp1"
    volumegroup: "test_volumegroup"
- name: Create a thin-provisioned volume
  ibm.storage_virtualize.ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: "{{ log_path }}"
    name: "volume_name"
    state: "present"
    pool: "pool_name"
    size: "1"
    unit: "gb"
    iogrp: "io_grp0, io_grp1"
    thin: true
    buffersize: 10%
- name: Create a compressed volume
  ibm.storage_virtualize.ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: "{{ log_path }}"
    name: "volume_name"
    state: "present"
    pool: "pool_name"
    size: "1"
    unit: "gb"
    iogrp: "io_grp0, io_grp1"
    compressed: true
    buffersize: 10%
- name: Creating a volume with iogrp- io_grp0
  ibm.storage_virtualize.ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: "{{ log_path }}"
    name: "volume_name"
    state: "present"
    pool: "pool_name"
    size: "1"
    unit: "gb"
    iogrp: "io_grp0"
- name: Create thinclone volume from volume vol1
  ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "vol1_thinclone"
    fromsourcevolume: "vol1"
    state: "present"
    pool: "pool0"
- name: Create clone volume from volume vol1
  ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "vol1_clone"
    fromsourcevolume: "vol1"
    state: "present"
    pool: "pool0"
- name: Adding a new iogrp- io_grp1
  ibm.storage_virtualize.ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: "{{ log_path }}"
    name: "volume_name"
    state: "present"
    pool: "pool_name"
    size: "1"
    unit: "gb"
    iogrp: "io_grp0, iogrp1"
- name: Rename an existing volume
  ibm.storage_virtualize.ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    old_name: "volume_name"
    name: "new_volume_name"
    state: "present"
- name: Convert a thinclone volume to clone
  ibm.storage_virtualize.ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "vol0-0"
    type: "clone"
    log_path: "{{ log_path }}"
    state: "present"
- name: Convert list of thinclone volumes to clone
  ibm.storage_virtualize.ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "vol0:vol1:vol2"
    type: "clone"
    log_path: "{{ log_path }}"
    state: "present"
- name: Enable cloud backup in an existing volume
  ibm.storage_virtualize.ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "volume_name"
    enable_cloud_snapshot: true
    cloud_account_name: "aws_acc"
    state: "present"
- name: Delete a volume
  ibm.storage_virtualize.ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: "{{ log_path }}"
    name: "new_volume_name"
    state: "absent"
- name: Delete a volume and remove associated host mappings, remote copy relationships, and flashcopy mappings
  ibm.storage_virtualize.ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: "{{ log_path }}"
    name: "new_volume_name"
    state: "absent"
    unmap: ['host_mappings', 'remotecopy_relationships', 'flashcopy_mappings']
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (
    IBMSVCRestApi,
    svc_argument_spec,
    get_logger,
    strtobool
)
from ansible.module_utils._text import to_native
import random


class IBMSVCvolume(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(type='str', required=True, choices=['absent', 'present']),
                pool=dict(type='str', required=False),
                size=dict(type='str', required=False),
                warning=dict(type='int', required=False),
                unit=dict(type='str', default='mb', choices=['b', 'kb',
                                                             'mb', 'gb',
                                                             'tb', 'pb']),
                buffersize=dict(type='str', required=False),
                iogrp=dict(type='str', required=False),
                volumegroup=dict(type='str', required=False),
                novolumegroup=dict(type='bool', required=False),
                unmap=dict(type='list', elements='str', required=False, choices=['host_mappings',
                                                                                 'remotecopy_relationships',
                                                                                 'flashcopy_mappings']),
                thin=dict(type='bool', required=False),
                compressed=dict(type='bool', required=False),
                deduplicated=dict(type='bool', required=False),
                old_name=dict(type='str', required=False),
                enable_cloud_snapshot=dict(type='bool'),
                cloud_account_name=dict(type='str'),
                type=dict(type='str', required=False, choices=['clone', 'thinclone']),
                fromsourcevolume=dict(type='str', required=False),
                allow_hs=dict(type='bool', default=False)
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required Parameters
        self.name = self.module.params['name']
        self.state = self.module.params['state']

        # Optional Parameters
        self.pool = self.module.params['pool']
        self.size = self.module.params['size']
        self.warning = self.module.params['warning']
        self.unit = self.module.params['unit']
        self.iogrp = self.module.params['iogrp']
        self.buffersize = self.module.params['buffersize']
        self.volumegroup = self.module.params['volumegroup']
        self.novolumegroup = self.module.params['novolumegroup']
        self.thin = self.module.params['thin']
        self.compressed = self.module.params['compressed']
        self.deduplicated = self.module.params['deduplicated']
        self.old_name = self.module.params['old_name']
        self.enable_cloud_snapshot = self.module.params['enable_cloud_snapshot']
        self.cloud_account_name = self.module.params['cloud_account_name']
        self.allow_hs = self.module.params['allow_hs']
        self.type = self.module.params['type']
        self.fromsourcevolume = self.module.params['fromsourcevolume']
        self.unmap = self.module.params['unmap']

        # internal variable
        self.changed = False

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

    # assemble iogrp
    def assemble_iogrp(self):
        if self.iogrp:
            temp = []
            invalid = []
            active_iogrp = []
            existing_iogrp = []
            if self.iogrp:
                existing_iogrp = [item.strip() for item in self.iogrp.split(',') if item]
            uni_exi_iogrp = set(existing_iogrp)
            if len(existing_iogrp) != len(uni_exi_iogrp):
                self.module.fail_json(msg='Duplicate iogrp detected.')
            active_iogrp = [item['name'] for item in self.restapi.svc_obj_info('lsiogrp', None, None) if int(item['node_count']) > 0]
            for item in existing_iogrp:
                item = item.strip()
                if item not in active_iogrp:
                    invalid.append(item)
                else:
                    temp.append(item)
            if invalid:
                self.module.fail_json(msg='Empty or non-existing iogrp detected: {0}'.format(invalid))
            self.iogrp = temp

    # for validating mandatory parameters of the module
    def mandatory_parameter_validation(self):
        missing = [item[0] for item in [('name', self.name), ('state', self.state)] if not item[1]]
        if missing:
            self.module.fail_json(msg='Missing mandatory parameter: [{0}]'.format(', '.join(missing)))
        if self.volumegroup and self.novolumegroup:
            self.module.fail_json(msg='Mutually exclusive parameters detected: [volumegroup] and [novolumegroup]')
        if self.thin and self.compressed:
            self.module.fail_json(msg='Mutually exclusive parameters detected: [thin] and [compressed]')
        if self.state == 'present' and self.unmap is not None:
            self.module.fail_json(msg='Parameter [unmap] cannot be specified when creating or updating a volume.')

    # for validating parameter while removing an existing volume
    def volume_deletion_parameter_validation(self):
        invalids = ('pool', 'size', 'iogrp', 'buffersize', 'volumegroup', 'novolumegroup',
                    'thin', 'compressed', 'deduplicated', 'old_name', 'enable_cloud_snapshot',
                    'cloud_account_name', 'allow_hs', 'type', 'fromsourcevolume', 'warning')

        invalid_params = ', '.join((param for param in invalids if getattr(self, param)))

        if invalid_params:
            self.module.fail_json(
                msg='Following parameter(s) are invalid while deletion of volume: {0}'.format(invalid_params)
            )

    # for validating parameter while creating a volume
    def volume_creation_parameter_validation(self):
        if self.enable_cloud_snapshot in {True, False}:
            self.module.fail_json(msg='Following parameter not applicable for creation: enable_cloud_snapshot')

        if self.cloud_account_name:
            self.module.fail_json(msg='Following parameter not applicable for creation: cloud_account_name')

        if self.old_name:
            self.module.fail_json(msg='Parameter [old_name] is not supported during volume creation.')

        if (self.type and not self.fromsourcevolume) or (self.fromsourcevolume and not self.type):
            self.module.fail_json(msg='Parameters [type] and [fromsourcevolume] parameters must be used together')

        if (self.warning) and not self.thin and not self.compressed:
            self.module.fail_json(msg='Parameter [warning] is invalid without [thin] or [compressed]')

        missing = []
        if self.type and self.fromsourcevolume:
            if not self.pool:
                missing = ['pool']
            if self.size:
                self.module.fail_json(msg='Parameter [size] is invalid while creating clone or thinclone')
        else:
            missing = [item[0] for item in [('pool', self.pool), ('size', self.size)] if not item[1]]

        if missing:
            self.module.fail_json(msg='Missing required parameter(s) while creating: [{0}]'.format(', '.join(missing)))

    # for validating parameter while renaming a volume
    def parameter_handling_while_renaming(self):
        if not self.old_name:
            self.module.fail_json(msg="Parameter is required while renaming: old_name")
        parameters = {
            "pool": self.pool,
            "size": self.size,
            "iogrp": self.iogrp,
            "buffersize": self.buffersize,
            "volumegroup": self.volumegroup,
            "novolumegroup": self.novolumegroup,
            "thin": self.thin,
            "compressed": self.compressed,
            "deduplicated": self.deduplicated,
            "type": self.type,
            "fromsourcevolume": self.fromsourcevolume
        }
        parameters_exists = [parameter for parameter, value in parameters.items() if value]
        if parameters_exists:
            self.module.fail_json(msg="Parameters {0} not supported while renaming a volume.".format(parameters_exists))

    # for validating if volume type is supported or not
    def validate_volume_type(self, data):
        unsupported_volume = False

        # The value many indicates that the volume has more than one copy
        if data[0]['type'] == "many":
            unsupported_volume = True
        if not unsupported_volume:
            relationship_name = data[0]['RC_name']
            if relationship_name:
                rel_data = self.restapi.svc_obj_info(cmd='lsrcrelationship', cmdopts=None, cmdargs=[relationship_name])
                if rel_data['copy_type'] == "activeactive" and not self.allow_hs:
                    unsupported_volume = True
        if unsupported_volume:
            self.module.fail_json(msg="The module cannot be used for managing Mirrored volume.")

    # function to get existing volume data
    def get_existing_volume(self, volume_name):
        return self.restapi.svc_obj_info(
            'lsvdisk', {'bytes': True}, [volume_name]
        )

    def get_all_target_volumes(self, criteria=None):
        # This function does following:
        # 1. It fetches a set of volumes from SVC in all_vols_set
        # 2. It converts self.name into a provided_vols_set
        # 3. It gets common volumes set from both that meet the criteria
        # 4. If any user-provide volume(s) do not exist on the cluster, returns error
        # 5. It sets a new attribute self.target_vols_list_str which is a string formed
        #    by joining colon-separated list of common volumes.

        all_vols_set = set()
        self.target_vols_list_str = ''

        if self.module.check_mode:
            self.changed = True
            return

        cmdopts = {}
        if criteria:
            cmdopts['filtervalue'] = criteria
        data = self.restapi.svc_obj_info('lsvdisk', cmdopts, None)
        if data:
            for item in data:
                all_vols_set.add(item['name'])

        user_provided_vols_set = set(self.name.split(':'))
        invalid_vols_list = list(user_provided_vols_set.difference(all_vols_set))
        if invalid_vols_list:
            self.module.fail_json(msg="CMMVC9855E The command failed because one or more of"
                                  " the specified volumes does not exist.")

        target_vols_list = []
        if data:
            for item in data:
                if item['name'] in user_provided_vols_set and item['volume_type'] == "thinclone":
                    target_vols_list.append(item['name'])
        self.target_vols_list_str = ':'.join(target_vols_list)
        self.log("Volume(s) that need to be converted from thinclone to clone: [%s].", self.target_vols_list_str)

        return

    # function to get list of associated iogrp to a volume
    def get_existing_iogrp(self):
        response = []
        data = self.restapi.svc_obj_info(
            'lsvdiskaccess', None, [self.name]
        )
        if data:
            for item in data:
                response.append(item['IO_group_name'])
        return response

    # function to create a transient (short-lived) snapshot
    # return value: snapshot_id
    def create_transient_snapshot(self):
        # Required parameters
        snapshot_cmd = 'addsnapshot'
        snapshot_opts = {}
        snapshot_name = 'snapshot_' + ''.join(random.choices('0123456789', k=10))

        snapshot_opts['name'] = snapshot_name

        # Optional parameters
        snapshot_opts['pool'] = self.module.params.get('pool', '')
        snapshot_opts['volumes'] = self.module.params.get('fromsourcevolume', '')
        snapshot_opts['retentionminutes'] = 5

        addsnapshot_output = self.restapi.svc_run_command(snapshot_cmd, snapshot_opts, cmdargs=None, timeout=10)
        snapshot_id = addsnapshot_output['id']

        return snapshot_id

    # function to create a new volume
    def create_volume(self):
        self.volume_creation_parameter_validation()
        if self.module.check_mode:
            self.changed = True
            return
        cmd = 'mkvolume'
        cmdopts = {}
        if self.pool:
            cmdopts['pool'] = self.pool
        if self.size:
            cmdopts['size'] = self.size
        if self.unit:
            cmdopts['unit'] = self.unit
        if self.iogrp:
            cmdopts['iogrp'] = self.iogrp[0]
        if self.volumegroup:
            cmdopts['volumegroup'] = self.volumegroup
        if self.thin:
            cmdopts['thin'] = self.thin
        if self.compressed:
            cmdopts['compressed'] = self.compressed
        if self.deduplicated:
            cmdopts['deduplicated'] = self.deduplicated
        if self.buffersize:
            cmdopts['buffersize'] = self.buffersize
        if self.name:
            cmdopts['name'] = self.name
        if self.warning:
            cmdopts['warning'] = str(self.warning) + '%'
        if self.type:
            cmdopts['type'] = self.type
            snapshot_id = self.create_transient_snapshot()
            cmdopts['fromsnapshotid'] = snapshot_id
        if self.fromsourcevolume:
            cmdopts['fromsourcevolume'] = self.fromsourcevolume

        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        if result and 'message' in result:
            self.changed = True
            self.log("create volume result message %s", result['message'])
        else:
            self.module.fail_json(
                msg="Failed to create volume [%s]" % self.name)

    # function to remove an existing volume
    def remove_volume(self):
        self.volume_deletion_parameter_validation()
        cmdopts = {}
        if self.module.check_mode:
            self.changed = True
            return
        name_params_map = {
            'host_mappings': 'removehostmappings',
            'remotecopy_relationships': 'removercrelationships',
            'flashcopy_mappings': 'removefcmaps'
        }
        if self.unmap:
            for name in self.unmap:
                cmdopts[name_params_map[name]] = True

        self.restapi.svc_run_command(
            'rmvolume', cmdopts, [self.name]
        )
        self.changed = True

    # function that data in other units to b
    def convert_to_bytes(self):
        return int(self.size) * (1024 ** (['b', 'kb', 'mb', 'gb', 'tb', 'pb'].index((self.unit).lower())))

    # function to probe an existing volume
    def probe_volume(self, data):
        props = {}
        # check for changes in iogrp
        if self.iogrp:
            input_iogrp = set(self.iogrp)
            existing_iogrp = set(self.get_existing_iogrp())
            if input_iogrp ^ existing_iogrp:
                iogrp_to_add = input_iogrp - existing_iogrp
                iogrp_to_remove = existing_iogrp - input_iogrp
                if iogrp_to_add:
                    props['iogrp'] = {
                        'add': list(iogrp_to_add)
                    }
                if iogrp_to_remove:
                    props['iogrp'] = {
                        'remove': list(iogrp_to_remove)
                    }
        # check for changes in volume size
        if self.size:
            input_size = self.convert_to_bytes()
            existing_size = int(data[0]['capacity'])
            if input_size != existing_size:
                if input_size > existing_size:
                    props['size'] = {
                        'expand': input_size - existing_size
                    }
                elif existing_size > input_size:
                    props['size'] = {
                        'shrink': existing_size - input_size
                    }
        if self.warning:
            # Check for standard or compressed volume
            if (data[0]['capacity'] != data[1]['real_capacity']) or (data[1]['compressed_copy'] == 'yes'):
                if (int(data[1]['warning']) != (self.warning)):
                    props['warning'] = str(self.warning) + '%'
            else:
                self.module.fail_json(msg='Parameter [warning] is applicable only for thin-provisioned and compressed volumes.')

        # check for changes in volumegroup
        if self.volumegroup:
            if self.volumegroup != data[0]['volume_group_name']:
                props['volumegroup'] = {
                    'name': self.volumegroup
                }
        # check for presence of novolumegroup
        if self.novolumegroup:
            if data[0]['volume_group_name']:
                props['novolumegroup'] = {
                    'status': True
                }
        # check for change in -thin parameter
        if self.thin is not None:
            if self.thin is True:
                # a standard volume or a compressed volume
                if (data[0]['capacity'] == data[1]['real_capacity']) or (data[1]['compressed_copy'] == 'yes'):
                    props['thin'] = {
                        'status': True
                    }
            else:
                if (data[0]['capacity'] != data[1]['real_capacity']) or (data[1]['compressed_copy'] == 'no'):
                    props['thin'] = {
                        'status': True
                    }
        # check for change in -compressed parameter
        if self.compressed is True:
            # not a compressed volume
            if data[1]['compressed_copy'] == 'no':
                props['compressed'] = {
                    'status': True
                }
        # check for change in -deduplicated parameter
        if self.deduplicated is True:
            # not a deduplicated volume
            if data[1]['deduplicated_copy'] == 'no':
                props['deduplicated'] = {
                    'status': True
                }
        # check for change in pool
        if self.pool:
            if self.pool != data[0]['mdisk_grp_name']:
                props['pool'] = {
                    'status': True
                }
        # Check for change in cloud backup
        if self.enable_cloud_snapshot is True:
            if not strtobool(data[0].get('cloud_backup_enabled')):
                props['cloud_backup'] = {'status': True}
        elif self.enable_cloud_snapshot is False:
            if strtobool(data[0].get('cloud_backup_enabled')):
                props['cloud_backup'] = {'status': True}

        if self.cloud_account_name:
            if self.cloud_account_name != data[0].get('cloud_account_name'):
                props['cloud_backup'] = {'status': True}

        # Check for change in fromsourcevolume
        if self.fromsourcevolume:
            if self.fromsourcevolume != data[0].get('source_volume_name'):
                props['fromsourcevolume'] = {'status': True}

        # Check for change in type
        if self.type:
            if self.type != data[0].get('volume_type'):
                props['type'] = {'status': True}

        return props

    # function to expand an existing volume size
    def expand_volume(self, expand_size):
        self.restapi.svc_run_command(
            'expandvdisksize',
            {'size': expand_size, 'unit': 'b'},
            [self.name]
        )
        self.changed = True

    # function to shrink an existing volume size
    def shrink_volume(self, shrink_size):
        self.restapi.svc_run_command(
            'shrinkvdisksize',
            {'size': shrink_size, 'unit': 'b'},
            [self.name]
        )
        self.changed = True

    # add iogrp
    def add_iogrp(self, list_of_iogrp):
        self.restapi.svc_run_command(
            'addvdiskaccess',
            {'iogrp': ':'.join(list_of_iogrp)},
            [self.name]
        )
        self.changed = True

    # remove iogrp
    def remove_iogrp(self, list_of_iogrp):
        self.restapi.svc_run_command(
            'rmvdiskaccess',
            {'iogrp': ':'.join(list_of_iogrp)},
            [self.name]
        )
        self.changed = True

    def update_cloud_backup(self):
        cmdopts = {}

        if self.enable_cloud_snapshot is True:
            cmdopts['backup'] = 'cloud'
            cmdopts['enable'] = True

        if self.enable_cloud_snapshot is False:
            cmdopts['backup'] = 'cloud'
            cmdopts['disable'] = True

        if self.cloud_account_name:
            cmdopts['account'] = self.cloud_account_name

        self.restapi.svc_run_command(
            'chvdisk',
            cmdopts,
            [self.name]
        )
        self.changed = True

    def convert_to_clone(self):
        # when check_mode is enabled
        if self.module.check_mode:
            self.msg = 'Skipping changes due to check mode.'
            self.changed = True
            return

        cmdopts = {}
        # For a list of volumes, target_volumes_list_str will be set by get_all_target_volumes()
        if hasattr(self, 'target_vols_list_str') and self.target_vols_list_str != '':
            cmdopts['volumes'] = self.target_vols_list_str
        else:
            cmdopts['volumes'] = self.name
        cmdargs = None
        self.restapi.svc_run_command('converttoclone', cmdopts, cmdargs)
        self.msg = "Volume(s) [{0}] converted to clone.".format(self.name)
        self.changed = True
        return

    # function to update an existing volume
    def update_volume(self, modify):
        # raise error for unsupported parameter
        unsupported_parameters = ['pool', 'thin', 'compressed', 'deduplicated', 'fromsourcevolume']
        unsupported_exists = []
        for parameter in unsupported_parameters:
            if parameter in modify:
                unsupported_exists.append(parameter)
        if unsupported_exists:
            self.module.fail_json(msg='Update not supported for parameter: {0}'.format(unsupported_exists))
        # when check_mode is enabled
        if self.module.check_mode:
            self.changed = True
            return

        # updating iogrps of a volume
        if 'iogrp' in modify:
            if 'add' in modify['iogrp']:
                self.add_iogrp(modify['iogrp']['add'])
            if 'remove' in modify['iogrp']:
                self.remove_iogrp(modify['iogrp']['remove'])
        # updating size of a volume
        if 'size' in modify:
            if 'expand' in modify['size']:
                self.expand_volume(modify['size']['expand'])
            elif 'shrink' in modify['size']:
                self.shrink_volume(modify['size']['shrink'])

        if 'cloud_backup' in modify:
            self.update_cloud_backup()

        cmdopts = {}
        if 'volumegroup' in modify:
            cmdopts['volumegroup'] = modify['volumegroup']['name']
        if 'novolumegroup' in modify:
            cmdopts['novolumegroup'] = modify['novolumegroup']['status']
        if 'warning' in modify:
            cmdopts['warning'] = modify['warning']
        if cmdopts:
            self.restapi.svc_run_command(
                'chvdisk',
                cmdopts,
                [self.name]
            )
            self.changed = True

    # function for renaming an existing volume with a new name
    def volume_rename(self, volume_data):
        msg = None
        self.parameter_handling_while_renaming()
        old_volume_data = self.get_existing_volume(self.old_name)
        if not old_volume_data and not volume_data:
            self.module.fail_json(msg="Volume [{0}] does not exists.".format(self.old_name))
        elif old_volume_data and volume_data:
            self.module.fail_json(msg="Volume [{0}] already exists.".format(self.name))
        elif not old_volume_data and volume_data:
            msg = "Volume with name [{0}] already exists.".format(self.name)
        elif old_volume_data and not volume_data:
            # when check_mode is enabled
            if self.module.check_mode:
                self.changed = True
                return
            self.restapi.svc_run_command('chvdisk', {'name': self.name}, [self.old_name])
            self.changed = True
            msg = "Volume [{0}] has been successfully rename to [{1}]".format(self.old_name, self.name)
        return msg

    def apply(self):
        changed, msg, modify = False, None, {}
        self.mandatory_parameter_validation()

        if ':' in self.name and self.type == 'clone' and self.state == 'present':
            # Special handling for list of volumes
            # Only applicable for converting thinclone volumes list to clone
            self.get_all_target_volumes()
            # self.target_vols_list_str will be set after calling get_all_target_volumes()
            if self.target_vols_list_str != '':
                self.convert_to_clone()
                self.module.exit_json(msg=self.msg, changed=self.changed)
            else:
                self.msg = "Volume(s) [{0}] are not thinclone!!".format(self.name)
                self.module.exit_json(msg=self.msg, changed=self.changed)
        else:
            volume_data = self.get_existing_volume(self.name)

        if volume_data and self.type == 'clone' and not self.fromsourcevolume:
            # If an existing volume was passed along with type=clone
            # but not fromsourcevolume, user wants to convert thinclone to clone
            if volume_data[0].get('volume_type') == 'thinclone':
                # If volume is thinclone, convert it to clone.
                self.convert_to_clone()
                self.module.exit_json(msg=self.msg, changed=self.changed)
            else:
                # If volume is not thinclone, just return message.
                # This is for cases, where it was either already done
                # the last time it was run, or was never a thinclone.
                self.module.exit_json(msg='Volume {0} is not a thinclone.'.format(self.name), changed=self.changed)

        if self.state == "present" and self.old_name:
            msg = self.volume_rename(volume_data)
        elif self.state == "absent" and self.old_name:
            self.module.fail_json(msg="Rename functionality is not supported when 'state' is absent.")
        else:
            if self.state == 'present':
                self.assemble_iogrp()
            if volume_data:
                self.validate_volume_type(volume_data)
                if self.state == 'absent':
                    changed = True
                elif self.state == 'present':
                    if self.type or self.fromsourcevolume:
                        # Both type and fromsourcevolume needed together
                        self.volume_creation_parameter_validation()
                        if ((volume_data[0].get('source_volume_name') and not self.fromsourcevolume) or
                                (volume_data[0].get('volume_type') and not self.type)):
                            changed = True

                    modify = self.probe_volume(volume_data)
                    if modify:
                        changed = True
            else:
                if self.state == 'present':
                    changed = True
            if changed:
                if self.state == 'present':
                    if not volume_data:
                        self.create_volume()
                        if isinstance(self.iogrp, list):
                            if len(self.iogrp) > 1:
                                self.add_iogrp(self.iogrp[1:])
                        msg = 'volume [%s] has been created' % self.name
                    else:
                        if modify:
                            self.update_volume(modify)
                            msg = 'volume [%s] has been modified' % self.name
                elif self.state == 'absent':
                    self.remove_volume()
                    msg = 'volume [%s] has been deleted.' % self.name
            else:
                if self.state == 'absent':
                    msg = "volume [%s] did not exist." % self.name
                else:
                    msg = "volume [%s] already exists." % self.name
        if self.module.check_mode:
            msg = 'Skipping changes due to check mode.'
            self.log('skipping changes due to check mode.')

        self.module.exit_json(msg=msg, changed=self.changed)


def main():
    v = IBMSVCvolume()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
