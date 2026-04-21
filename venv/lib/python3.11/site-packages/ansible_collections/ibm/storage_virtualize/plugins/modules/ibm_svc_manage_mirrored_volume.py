#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 IBM CORPORATION
# Author(s): Rohit Kumar <rohit.kumar6@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_manage_mirrored_volume
short_description: This module manages mirrored volumes on IBM Storage Virtualize
                   family systems
description:
  - Ansible interface to manage 'mkvolume', 'addvolumecopy', 'rmvolumecopy', and 'rmvolume' volume commands.
version_added: "1.4.0"
options:
  name:
    description:
      - Specifies the name to assign to the new volume.
    required: true
    type: str
  state:
    description:
      - Creates (C(present)) or removes (C(absent)) a mirrored volume.
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
  poolA:
    description:
    - Specifies the name of first storage pool to be used when creating a mirrored volume.
    type: str
  poolB:
    description:
    - Specifies the name of second storage pool to be used when creating a mirrored volume.
    type: str
  type:
    description:
    - Specifies the desired volume type.
    - When the type is C(local hyperswap), a HyperSwap volume gets created.
    - When the type is C(standard) and values for I(PoolA) and I(PoolB) arguments are also specified,
      a "standard mirror" volume gets created.
    - If a "standard" mirrored volume exists and either I(PoolA) or I(PoolB)
      is specified, the mirrored volume gets converted to a standard volume.
    choices: [ local hyperswap, standard ]
    type: str
  thin:
    description:
    - Specifies if the volume to be created is thin-provisioned.
    type: bool
  compressed:
    description:
    - Specifies if the volume to be created is compressed.
    type: bool
  deduplicated:
    description:
    - Specifies if the volume to be created is deduplicated.
    type: bool
  grainsize:
    description:
    - Specifies the grain size (in KB) to use when
      creating the HyperSwap volume.
    type: str
  rsize:
    description:
    - Specifies the rsize (buffersize) in %. Defines how much physical space
      is initially allocated to the thin-provisioned or compressed volume.
    type: str
  size:
    description:
    - Specifies the size of mirrored volume in MB. This can also be used
      to resize a mirrored volume. When resizing, only mandatory parameters can
      be passed.
    type: str
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
    - Rohit Kumar(@rohitk-github)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create a HyperSwap volume
  ibm.storage_virtualize.ibm_svc_manage_mirrored_volume:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    type: "local hyperswap"
    name: "vol1"
    state: present
    poolA: "pool1"
    poolB: "pool2"
    size: "1024"
- name: Create a thin-provisioned HyperSwap volume
  ibm.storage_virtualize.ibm_svc_manage_mirrored_volume:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    type: "local hyperswap"
    name: "vol2"
    state: present
    poolA: "pool1"
    poolB: "pool2"
    size: "1024"
    thin: true
- name: Delete a mirrored volume
  ibm.storage_virtualize.ibm_svc_manage_mirrored_volume:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    name: "vol2"
    state: absent
- name: Create a standard mirror volume
  block:
    - name: Create Volume
      ibm.storage_virtualize.ibm_svc_manage_mirrored_volume:
        clustername: "{{ clustername }}"
        username: "{{ username }}"
        password: "{{ password }}"
        log_path: /tmp/playbook.debug
        name: "vol4"
        state: present
        type: "standard"
        poolA: "pool1"
        poolB: "pool3"
- name: Resize an existing mirrored volume
  block:
    - name: Resize an existing mirrored volume
      ibm.storage_virtualize.ibm_svc_manage_mirrored_volume:
        clustername: "{{ clustername }}"
        username: "{{ username }}"
        password: "{{ password }}"
        log_path: /tmp/playbook.debug
        name: "vol1"
        state: present
        size: "{{ new_size }}"
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCvolume(object):
    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(type='str', required=True, choices=['absent',
                                                               'present']),
                poolA=dict(type='str', required=False),
                poolB=dict(type='str', required=False),
                size=dict(type='str', required=False),
                thin=dict(type='bool', required=False),
                type=dict(type='str', required=False, choices=['local hyperswap', 'standard']),
                grainsize=dict(type='str', required=False),
                rsize=dict(type='str', required=False),
                compressed=dict(type='bool', required=False),
                deduplicated=dict(type='bool', required=False)

            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)
        self.vdisk_type = ""
        self.discovered_poolA = ""
        self.discovered_poolB = ""
        self.discovered_standard_vol_pool = ""
        self.poolA_data = ""
        self.poolB_data = ""
        self.isdrp = False
        self.expand_flag = False
        self.shrink_flag = False

        # logging setup
        log_path = self.module.params.get('log_path')
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required
        self.name = self.module.params.get('name')
        self.state = self.module.params.get('state')

        if not self.name:
            self.module.fail_json(msg="Missing mandatory parameter: name")
        if not self.state:
            self.module.fail_json(msg="Missing mandatory parameter: state")

        # Optional
        self.poolA = self.module.params.get('poolA')
        self.poolB = self.module.params.get('poolB')
        self.size = self.module.params.get('size')
        self.type = self.module.params.get('type')
        self.compressed = self.module.params.get('compressed')
        self.thin = self.module.params.get('thin')
        self.deduplicated = self.module.params.get('deduplicated')
        self.rsize = self.module.params.get('rsize')
        self.grainsize = self.module.params.get('grainsize')

        self.restapi = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params.get('clustername'),
            domain=self.module.params.get('domain'),
            username=self.module.params.get('username'),
            password=self.module.params.get('password'),
            validate_certs=self.module.params.get('validate_certs'),
            log_path=log_path,
            token=self.module.params['token']
        )

    def get_existing_vdisk(self):
        self.log("Entering function get_existing_vdisk")
        cmd = 'lsvdisk'
        cmdargs = {}
        cmdopts = {'bytes': True}
        cmdargs = [self.name]
        existing_vdisk_data = self.restapi.svc_obj_info(cmd, cmdopts, cmdargs)
        return existing_vdisk_data

    def basic_checks(self, data):
        self.log("Entering function basic_checks")
        if self.poolA:
            self.poolA_data = self.restapi.svc_obj_info(cmd='lsmdiskgrp', cmdopts=None, cmdargs=[self.poolA])
            if not self.poolA_data:
                self.module.fail_json(msg="PoolA does not exist")
        if self.poolB:
            self.poolB_data = self.restapi.svc_obj_info(cmd='lsmdiskgrp', cmdopts=None, cmdargs=[self.poolB])
            if not self.poolB_data:
                self.module.fail_json(msg="PoolB does not exist")
        if self.state == "present" and not self.type and not self.size:
            self.module.fail_json(msg="missing required argument: type")
        if self.poolA and self.poolB:
            if self.poolA == self.poolB:
                self.module.fail_json(msg="poolA and poolB cannot be same")
            siteA, siteB = self.discover_site_from_pools()
            if siteA != siteB and self.type == "standard":
                self.module.fail_json(msg="To create Standard Mirrored volume, provide pools belonging to same site.")
        if not self.poolA and not self.poolB and self.state == "present" and not self.size:
            self.module.fail_json(msg="Both poolA and poolB cannot be empty")
        if self.type == "local hyperswap" and self.state != 'absent':
            if not self.poolA or not self.poolB:
                self.module.fail_json(msg="Both poolA and poolB need to be passed when type is 'local hyperswap'")

    def discover_vdisk_type(self, data):
        # Discover the vdisk type. this function is called if the volume already exists.
        self.log("Entering function discover_vdisk_type")
        is_std_mirrored_vol = False
        is_hs_vol = False
        if data[0]['type'] == "many":
            is_std_mirrored_vol = True
            self.discovered_poolA = data[1]['mdisk_grp_name']
            self.discovered_poolB = data[2]['mdisk_grp_name']
            self.log("The discovered standard mirrored volume \"%s\" belongs to \
pools \"%s\" and \"%s\"", self.name, self.discovered_poolA, self.discovered_poolB)

        relationship_name = data[0]['RC_name']
        if relationship_name:
            rel_data = self.restapi.svc_obj_info(cmd='lsrcrelationship', cmdopts=None, cmdargs=[relationship_name])
            if rel_data['copy_type'] == "activeactive":
                is_hs_vol = True
            if is_hs_vol:
                master_vdisk = rel_data['master_vdisk_name']
                aux_vdisk = rel_data['aux_vdisk_name']
                master_vdisk_data = self.restapi.svc_obj_info(cmd='lsvdisk', cmdopts=None, cmdargs=[master_vdisk])
                aux_vdisk_data = self.restapi.svc_obj_info(cmd='lsvdisk', cmdopts=None, cmdargs=[aux_vdisk])
                if is_std_mirrored_vol:
                    self.discovered_poolA = master_vdisk_data[1]['mdisk_grp_name']
                    self.discovered_poolB = aux_vdisk_data[1]['mdisk_grp_name']
                    self.log("The discovered mixed volume \"%s\" belongs to pools \"%s\" and \"%s\"", self.name, self.discovered_poolA, self.discovered_poolB)
                else:
                    self.discovered_poolA = master_vdisk_data[0]['mdisk_grp_name']
                    self.discovered_poolB = aux_vdisk_data[0]['mdisk_grp_name']
                    self.log("The discovered HyperSwap volume \"%s\" belongs to pools\
                     \"%s\" and \"%s\"", self.name, self.discovered_poolA, self.discovered_poolB)

        if is_std_mirrored_vol and is_hs_vol:
            self.module.fail_json(msg="Unsupported Configuration: Both HyperSwap and Standard Mirror \
are configured on this volume")
        elif is_hs_vol:
            vdisk_type = "local hyperswap"
        elif is_std_mirrored_vol:
            vdisk_type = "standard mirror"
        if not is_std_mirrored_vol and not is_hs_vol:
            mdisk_grp_name = data[0]['mdisk_grp_name']
            self.discovered_standard_vol_pool = mdisk_grp_name
            vdisk_type = "standard"
            self.log("The standard volume %s belongs to pool \"%s\"", self.name, self.discovered_standard_vol_pool)
        return vdisk_type

    def discover_site_from_pools(self):
        self.log("Entering function discover_site_from_pools")
        poolA_site = self.poolA_data['site_name']
        poolB_site = self.poolB_data['site_name']
        return poolA_site, poolB_site

    def vdisk_probe(self, data):
        self.log("Entering function vdisk_probe")
        props = []
        resizevolume_flag = False
        if self.type == "local hyperswap" and self.vdisk_type == "standard mirror":
            self.module.fail_json(msg="You cannot \
update the topolgy from standard mirror to HyperSwap")
        if (self.vdisk_type == "local hyperswap" or self.vdisk_type == "standard mirror") and self.size:
            size_in_bytes = int(self.size) * 1024 * 1024
            existing_size = int(data[0]['capacity'])
            if size_in_bytes != existing_size:
                resizevolume_flag = True
                props += ['resizevolume']
            if size_in_bytes > existing_size:
                self.changebysize = size_in_bytes - existing_size
                self.expand_flag = True
            elif size_in_bytes < existing_size:
                self.changebysize = existing_size - size_in_bytes
                self.shrink_flag = True
        if self.poolA and self.poolB:
            if self.vdisk_type == "local hyperswap" and self.type == "standard":
                self.module.fail_json(msg="HyperSwap Volume cannot be converted to standard mirror")
            if self.vdisk_type == "standard mirror" or self.vdisk_type == "local hyperswap":
                if (self.poolA == self.discovered_poolA or self.poolA == self.discovered_poolB)\
                   and (self.poolB == self.discovered_poolA or self.poolB == self.discovered_poolB) and not resizevolume_flag:
                    return props
                elif not resizevolume_flag:
                    self.module.fail_json(msg="Pools for Standard Mirror or HyperSwap volume cannot be updated")
            elif self.vdisk_type == "standard" and self.type == "local hyperswap":
                # input poolA or poolB must belong to given Volume
                if self.poolA == self.discovered_standard_vol_pool or self.poolB == self.discovered_standard_vol_pool:
                    props += ['addvolumecopy']
                else:
                    self.module.fail_json(msg="One of the input pools must belong to the Volume")
            elif self.vdisk_type == "standard" and self.type == "standard":
                if self.poolA == self.discovered_standard_vol_pool or self.poolB == self.discovered_standard_vol_pool:
                    props += ['addvdiskcopy']
                else:
                    self.module.fail_json(msg="One of the input pools must belong to the Volume")
            elif self.vdisk_type and not self.type:
                self.module.fail_json(msg="missing required argument: type")
        elif not self.poolA or not self.poolB:
            if self.vdisk_type == "standard":
                if self.poolA == self.discovered_standard_vol_pool or self.poolB == self.discovered_standard_vol_pool:
                    self.log("Standard Volume already exists, no modifications done")
                    return props
            if self.poolA:
                if self.poolA == self.discovered_poolA or self.poolA == self.discovered_poolB:
                    props += ['rmvolumecopy']
                else:
                    self.module.fail_json(msg="One of the input pools must belong to the Volume")
            elif self.poolB:
                if self.poolB == self.discovered_poolA or self.poolB == self.discovered_poolB:
                    props += ['rmvolumecopy']
                else:
                    self.module.fail_json(msg="One of the input pools must belong to the Volume")
        if not (self.poolA or not self.poolB) and not self.size:
            if (self.system_topology == "hyperswap" and self.type == "local hyperswap"):
                self.module.fail_json(msg="Type must be standard if either PoolA or PoolB is not specified.")
        return props

    def resizevolume(self):
        if self.thin is not None or self.deduplicated is not None or self.rsize is not None or self.grainsize is not None \
           or self.compressed is not None or self.poolA is not None or self.poolB is not None or self.type is not None:
            self.module.fail_json(msg="Volume already exists, Parameter 'thin', 'deduplicated', 'rsize', 'grainsize', 'compressed' \
'PoolA', 'PoolB' or 'type' cannot be passed while resizing the volume.")

        if self.module.check_mode:
            self.changed = True
            return

        cmd = ""
        cmdopts = {}
        if self.vdisk_type == "local hyperswap" and self.expand_flag:
            cmd = "expandvolume"
        elif self.vdisk_type == "local hyperswap" and self.shrink_flag:
            self.module.fail_json(msg="Size of a HyperSwap Volume cannot be shrinked")
        elif self.vdisk_type == "standard mirror" and self.expand_flag:
            cmd = "expandvdisksize"
        elif self.vdisk_type == "standard mirror" and self.shrink_flag:
            cmd = "shrinkvdisksize"
        elif self.vdisk_type != "standard mirror" or self.vdisk_type != "local hyperswap":
            self.module.fail_json(msg="The volume is not a mirror volume, Please use ibm_svc_manage_volume module for resizing standard volumes")
        cmdopts["size"] = str(self.changebysize)
        cmdopts["unit"] = "b"
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=[self.name])
        self.changed = True

    def volume_create(self):
        self.log("Entering function volume_create")
        if not self.size:
            self.module.fail_json(msg="You must pass in size to the module.")
        if not self.type:
            self.module.fail_json(msg="You must pass type to the module.")

        self.log("creating Volume '%s'", self.name)
        if self.module.check_mode:
            self.changed = True
            return

        # Make command
        cmd = 'mkvolume'
        cmdopts = {}
        if self.poolA and self.poolB:
            cmdopts['pool'] = self.poolA + ":" + self.poolB
        if self.size:
            cmdopts['size'] = self.size
            cmdopts['unit'] = "mb"
        if self.grainsize:
            cmdopts['grainsize'] = self.grainsize
        if self.thin and self.rsize:
            cmdopts['thin'] = self.thin
            cmdopts['buffersize'] = self.rsize
        elif self.thin:
            cmdopts['thin'] = self.thin
        elif self.rsize and not self.thin:
            self.module.fail_json(msg="To configure 'rsize', parameter 'thin' should be passed and the value should be 'true'.")
        if self.compressed:
            cmdopts['compressed'] = self.compressed
        if self.thin:
            cmdopts['thin'] = self.thin
        if self.deduplicated:
            cmdopts['deduplicated'] = self.deduplicated
        cmdopts['name'] = self.name
        self.log("creating volume command %s opts %s", cmd, cmdopts)

        # Run command
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log("create volume result %s", result)

        if 'message' in result:
            self.changed = True
            self.log("create volume result message %s", result['message'])
        else:
            self.module.fail_json(
                msg="Failed to create volume [%s]" % self.name)

    def vdisk_create(self):
        self.log("Entering function vdisk_create")
        if not self.size:
            self.module.fail_json(msg="You must pass in size to the module.")
        if not self.type:
            self.module.fail_json(msg="You must pass type to the module.")

        self.log("creating Volume '%s'", self.name)
        # Make command
        cmd = 'mkvdisk'
        cmdopts = {}
        if self.poolA and self.poolB:
            cmdopts['mdiskgrp'] = self.poolA + ":" + self.poolB
        if self.size:
            cmdopts['size'] = self.size
            cmdopts['unit'] = "mb"
        if self.compressed:
            cmdopts['compressed'] = self.compressed
        if self.thin and self.rsize:
            cmdopts['rsize'] = self.rsize
        elif self.thin:
            cmdopts['rsize'] = "2%"
        elif self.rsize and not self.thin:
            self.module.fail_json(msg="To configure 'rsize', parameter 'thin' should be passed and the value should be 'true.'")
        if self.grainsize:
            cmdopts['grainsize'] = self.grainsize
        if self.deduplicated:
            if self.thin:
                cmdopts['autoexpand'] = True
                cmdopts['deduplicated'] = self.deduplicated
            else:
                self.module.fail_json(msg="To configure 'deduplicated', parameter 'thin' should be passed and the value should be 'true.'")
        cmdopts['name'] = self.name
        cmdopts['copies'] = 2
        if self.isdrp and self.thin:
            cmdopts['autoexpand'] = True
        self.log("creating volume command %s opts %s", cmd, cmdopts)

        if self.module.check_mode:
            self.changed = True
            return

        # Run command
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log("create volume result %s", result)

        if 'message' in result:
            self.changed = True
            self.log("create volume result message %s", result['message'])
        else:
            self.module.fail_json(
                msg="Failed to create Volume [%s]" % self.name)

    def addvolumecopy(self):
        self.log("Entering function addvolumecopy")
        cmd = 'addvolumecopy'
        cmdopts = {}
        if self.compressed:
            cmdopts['compressed'] = self.compressed
        if self.grainsize:
            cmdopts['grainsize'] = self.grainsize
        if self.thin and self.rsize:
            cmdopts['thin'] = self.thin
            cmdopts['buffersize'] = self.rsize
        elif self.thin:
            cmdopts['thin'] = self.thin
        elif self.rsize and not self.thin:
            self.module.fail_json(msg="To configure 'rsize', parameter 'thin' should be passed and the value should be 'true'.")
        if self.deduplicated:
            cmdopts['deduplicated'] = self.deduplicated
        if self.size:
            self.module.fail_json(msg="Parameter 'size' cannot be passed while converting a standard volume to Mirror Volume")
        if self.poolA and (self.poolB == self.discovered_standard_vol_pool and self.poolA != self.discovered_standard_vol_pool):
            cmdopts['pool'] = self.poolA
        elif self.poolB and (self.poolA == self.discovered_standard_vol_pool and self.poolB != self.discovered_standard_vol_pool):
            cmdopts['pool'] = self.poolB

        if self.module.check_mode:
            self.changed = True
            return

        cmdargs = [self.name]
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

    def addvdiskcopy(self):
        self.log("Entering function addvdiskcopy")
        cmd = 'addvdiskcopy'
        cmdopts = {}
        if self.size:
            self.module.fail_json(msg="Parameter 'size' cannot be passed while converting a standard volume to Mirror Volume")
        siteA, siteB = self.discover_site_from_pools()
        if siteA != siteB:
            self.module.fail_json(msg="To create Standard Mirrored volume, provide pools belonging to same site.")
        if self.poolA and (self.poolB == self.discovered_standard_vol_pool and self.poolA != self.discovered_standard_vol_pool):
            cmdopts['mdiskgrp'] = self.poolA
        elif self.poolB and (self.poolA == self.discovered_standard_vol_pool and self.poolB != self.discovered_standard_vol_pool):
            cmdopts['mdiskgrp'] = self.poolB
        else:
            self.module.fail_json(msg="One of the input pools must belong to the volume")
        if self.compressed:
            cmdopts['compressed'] = self.compressed
        if self.grainsize:
            cmdopts['grainsize'] = self.grainsize
        if self.thin and self.rsize:
            cmdopts['rsize'] = self.rsize
        elif self.thin:
            cmdopts['rsize'] = "2%"
        elif self.rsize and not self.thin:
            self.module.fail_json(msg="To configure 'rsize', parameter 'thin' should be passed and the value should be 'true'.")
        if self.deduplicated:
            if self.thin:
                cmdopts['deduplicated'] = self.deduplicated
                cmdopts['autoexpand'] = True
            else:
                self.module.fail_json(msg="To configure 'deduplicated', parameter 'thin' should be passed and the value should be 'true.'")
        if self.isdrp and self.thin:
            cmdopts['autoexpand'] = True
        if self.module.check_mode:
            self.changed = True
            return

        cmdargs = [self.name]
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

    def rmvolumecopy(self):
        self.log("Entering function rmvolumecopy")
        cmd = 'rmvolumecopy'

        if self.size or self.thin or self.deduplicated or self.rsize or self.grainsize or self.compressed:
            self.module.fail_json(msg="Parameter 'size', 'thin', 'deduplicated', 'rsize', 'grainsize' or 'compressed' \
cannot be passed while converting a Mirror Volume to Standard.")

        if self.module.check_mode:
            self.changed = True
            return
        cmdopts = {}
        if not self.poolA:
            if (self.poolB != self.discovered_poolA):
                cmdopts['pool'] = self.discovered_poolA
            else:
                cmdopts['pool'] = self.discovered_poolB
        elif not self.poolB:
            if (self.poolA != self.discovered_poolB):
                cmdopts['pool'] = self.discovered_poolB
            else:
                cmdopts['pool'] = self.discovered_poolA
        cmdargs = [self.name]
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

    def vdisk_update(self, modify):
        self.log("Entering function vdisk_update")
        if 'addvdiskcopy' in modify and 'resizevolume' in modify:
            self.module.fail_json(msg="You cannot resize the volume alongwith converting the volume to Standard Mirror")
        if 'addvolumecopy' in modify and 'resizevolume' in modify:
            self.module.fail_json(msg="You cannot resize the volume alongwith converting the volume to Local HyperSwap")
        if 'rmvolumecopy' in modify and 'resizevolume' in modify:
            self.module.fail_json(msg="You cannot resize the volume alongwith converting the Mirror volume to Standard")
        if 'addvolumecopy' in modify:
            self.addvolumecopy()
        elif 'addvdiskcopy' in modify:
            self.isdrpool()
            self.addvdiskcopy()
        elif 'rmvolumecopy' in modify:
            self.rmvolumecopy()
        elif 'resizevolume' in modify:
            self.resizevolume()

    def isdrpool(self):
        poolA_drp = self.poolA_data['data_reduction']
        poolB_drp = self.poolB_data['data_reduction']
        isdrpool_list = [poolA_drp, poolB_drp]
        if "yes" in isdrpool_list:
            self.isdrp = True

    def volume_delete(self):
        self.log("Entering function volume_delete")
        self.log("deleting volume '%s'", self.name)

        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'rmvolume'
        cmdopts = None
        cmdargs = [self.name]

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # rmvolume does not output anything when successful.
        self.changed = True

    def discover_system_topology(self):
        self.log("Entering function discover_system_topology")
        system_data = self.restapi.svc_obj_info(cmd='lssystem', cmdopts=None, cmdargs=None)
        sys_topology = system_data['topology']
        return sys_topology

    def apply(self):
        self.log("Entering function apply")
        changed = False
        msg = None
        modify = []
        vdisk_data = self.get_existing_vdisk()
        # Perform basic checks and fail the module with appropriate error msg if requirements are not satisfied
        self.basic_checks(vdisk_data)

        # Discover System Topology
        self.system_topology = self.discover_system_topology()
        if self.system_topology == "standard" and self.type == "local hyperswap":
            self.module.fail_json(msg="The system topology is Standard, HyperSwap actions are not supported.")

        if vdisk_data:
            if self.state == 'absent':
                self.log("CHANGED: volume exists, but requested state is 'absent'")
                changed = True
            elif self.state == 'present':
                # Discover the existing vdisk type.
                self.vdisk_type = self.discover_vdisk_type(vdisk_data)
                # Check if there is change in configuration
                modify = self.vdisk_probe(vdisk_data)
                if modify:
                    changed = True
        else:
            if self.state == 'present':
                if self.poolA and self.poolB:
                    self.log("CHANGED: volume does not exist, but requested state is 'present'")
                    changed = True
                else:
                    self.module.fail_json(msg="Volume does not exist, To create a Mirrored volume (standard mirror or HyperSwap), \
You must pass in poolA and poolB to the module.")

        if changed:
            if self.state == 'present':
                if not vdisk_data:
                    if not self.type:
                        self.module.fail_json(msg="missing required argument: type")
                    # create_vdisk_flag = self.discover_site_from_pools()
                    if self.type == "standard":
                        self.isdrpool()
                        self.vdisk_create()
                        msg = "Standard Mirrored Volume %s has been created." % self.name
                        changed = True
                    elif self.type == "local hyperswap":
                        # if not create_vdisk_flag:
                        self.volume_create()
                        msg = "HyperSwap Volume %s has been created." % self.name
                        changed = True
                else:
                    # This is where we would modify if required
                    self.vdisk_update(modify)
                    msg = "Volume [%s] has been modified." % self.name
                    changed = True
            elif self.state == 'absent':
                self.volume_delete()
                msg = "Volume [%s] has been deleted." % self.name
                changed = True

            if self.module.check_mode:
                msg = 'skipping changes due to check mode'
        else:
            self.log("exiting with no changes")
            if self.state == 'absent':
                msg = "Volume %s did not exist." % self.name
            else:
                msg = self.vdisk_type + " Volume [%s] already exists, no modifications done" % self.name

        self.module.exit_json(msg=msg, changed=changed)


def main():
    v = IBMSVCvolume()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
