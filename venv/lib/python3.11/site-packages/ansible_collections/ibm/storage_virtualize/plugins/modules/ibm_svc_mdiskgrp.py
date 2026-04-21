#!/usr/bin/python
# Copyright (C) 2020 IBM CORPORATION
# Author(s): Peng Wang <wangpww@cn.ibm.com>
#            Sanjaikumaar M <sanjaikumaar.m@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_mdiskgrp
short_description: This module manages pools on IBM Storage Virtualize family systems
description:
  - Ansible interface to manage 'mkmdiskgrp' and 'rmmdiskgrp' pool commands.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name to assign to the new pool.
    required: true
    type: str
  state:
    description:
      - Creates (C(present)) or removes (C(absent)) an MDisk group.
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
    - To generate a token, use the M(ibm.storage_virtualize.ibm_svc_auth) module.
    type: str
    version_added: '1.5.0'
  datareduction:
    description:
    - Defines use of data reduction pools (DRPs) on the MDisk group.
    - Applies when I(state=present), to create a pool.
    type: str
    default: 'no'
    choices: ['yes', 'no']
  easytier:
    description:
    - Defines use of easytier with the MDisk group.
    - Applies when I(state=present), to create a pool.
    type: str
    default: 'off'
    choices: ['on', 'off', 'auto']
  encrypt:
    description:
    - Defines use of encryption with the MDisk group.
    - Applies when I(state=present), to create a pool.
    type: str
    default: 'no'
    choices: ['yes', 'no']
  ext:
    description:
    - Specifies the size of the extents for this group in MB.
    - Applies when I(state=present), to create a pool.
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
  parentmdiskgrp:
    description:
      - Parentmdiskgrp for subpool.
      - Applies when I(state=present), to create a pool.
    type: str
  safeguarded:
    description:
      - Specify to create a safeguarded child pool.
      - Applicable only during child pool creation.
    type: bool
    version_added: 1.8.0
  noquota:
    description:
      - Specify to create a data reduction child pool.
      - I(noquota) and I(size) parameters are mutually exclusive.
      - I(noquota) parameter must be used with I(datareduction) set to yes to create a data reduction child pool.
      - I(noquota) parameter must be used with I(parentmdiskgrp) in a parent data reduction storage pool.
    type: bool
    version_added: 1.8.0
  unit:
    description:
      - Unit for subpool.
      - Applies when I(state=present), to create a pool.
    type: str
  provisioningpolicy:
    description:
      - Specify the name of the provisioning policy to map it with the pool.
      - Applies, when I(state=present).
    type: str
    version_added: 1.10.0
  noprovisioningpolicy:
    description:
      - Specify to unmap provisioning policy from the pool.
      - Applies, when I(state=present) to modify an existing pool.
    type: bool
    version_added: 1.10.0
  replicationpoollinkuid:
    description:
      - Specifies the replication pool unique identifier which should be same as the pool that present in the replication server.
      - Applies, when I(state=present).
      - Supported in SV build 8.5.2.1 or later.
    type: str
    version_added: 1.10.0
  resetreplicationpoollinkuid:
    description:
      - If set, any links between this pool on local system and pools on remote systems will be removed.
      - Applies, when I(state=present) to modify an existing pool.
      - Supported in SV build 8.5.2.1 or later.
    type: bool
    version_added: 1.10.0
  replication_partner_clusterid:
    description:
      - Specifies the id or name of the partner cluster which will be used for replication.
      - Applies, when I(state=present).
      - Supported in SV build 8.5.2.1 or later.
    type: str
    version_added: 1.10.0
  size:
    description:
      - Specifies the child pool capacity. The value must be
        a numeric value (and an integer multiple of the extent size).
      - Applies when I(state=present), to create a pool.
    type: int
  warning:
    description:
      - If specified, generates a warning when the used disk capacity in the storage pool first exceeds the specified threshold.
      - The default value is 80. To disable it, specify the value as 0.
      - Applies when I(state=present) while creating the pool.
    type: int
    version_added: '1.12.0'
  ownershipgroup:
    description:
      - Specifies the name of the ownershipgroup to map it with the pool.
      - Applies when I(state=present).
    type: str
    version_added: '1.12.0'
  noownershipgroup:
    description:
      - Specifies to unmap ownershipgroup from the pool.
      - Applies when I(state=present) to modify an existing pool.
    type: bool
    version_added: '1.12.0'
  vdiskprotectionenabled:
    description:
      - Specifies whether volume protection is enabled for this storage pool. The default value is 'yes'.
      - Applies when I(state=present).
    type: str
    choices: ['yes', 'no']
    version_added: '1.12.0'
  etfcmoverallocationmax:
    description:
      - Specifies the maximum over allocation which Easy Tier can migrate onto FlashCore Module arrays, when the array is used as the top
        tier in a multitier pool. The value acts as a multiplier of the physically available space.
      - The allowed values are a percentage in the range of 100% (default) to 400% or off. Setting the value to off disables this feature.
      - Applies when I(state=present).
    type: str
    version_added: '1.12.0'
  old_name:
    description:
      - Specifies the old name of an existing pool.
      - Applies when I(state=present), to rename the existing pool.
    type: str
    version_added: '1.12.0'

author:
    - Peng Wang(@wangpww)
    - Sanjaikumaar M (@sanjaikumaar)
    - Lavanya C R(@lavanya)
notes:
    - This module supports C(check_mode).
'''
EXAMPLES = '''
- name: Create mdisk group
  ibm.storage_virtualize.ibm_svc_mdiskgrp:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: pool1
    provisioningpolicy: pp0
    replicationpoollinkuid: '000000000000000'
    replication_partner_clusterid: '000000000032432342'
    etfcmoverallocationmax: 120
    state: present
    datareduction: 'no'
    easytier: auto
    encrypt: 'no'
    ext: 1024
- name: Create childpool with ownershipgroup
  ibm.storage_virtualize.ibm_svc_mdiskgrp:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: childpool0
    ownershipgroup: owner0
    parentmdiskgrp: pool1
    state: present
    datareduction: 'no'
    easytier: auto
    encrypt: 'no'
    ext: 1024
- name: Create a safeguarded backup location
  ibm.storage_virtualize.ibm_svc_mdiskgrp:
    clustername: "{{ clustername }}"
    token: "{{ results.token }}"
    log_path: "{{ log_path }}"
    parentmdiskgrp: Pool1
    name: Pool1child1
    datareduction: 'yes'
    safeguarded: 'True'
    ext: 1024
    noquota: 'True'
    state: present
- name: Delete mdisk group
  ibm.storage_virtualize.ibm_svc_mdiskgrp:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: pool1
    state: absent
- name: Delete a safeguarded backup location
  ibm.storage_virtualize.ibm_svc_mdiskgrp:
    clustername: "{{ clustername }}"
    token: "{{ results.token }}"
    log_path: "{{ log_path }}"
    parentmdiskgrp: Pool1
    name: Pool1child1
    state: absent
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger


class IBMSVCmdiskgrp(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(type='str', required=True, choices=['absent',
                                                               'present']),
                datareduction=dict(type='str', default='no', choices=['yes',
                                                                      'no']),
                easytier=dict(type='str', default='off', choices=['on', 'off',
                                                                  'auto']),
                encrypt=dict(type='str', default='no', choices=['yes', 'no']),
                ext=dict(type='int'),
                parentmdiskgrp=dict(type='str'),
                safeguarded=dict(type='bool'),
                noquota=dict(type='bool'),
                size=dict(type='int'),
                unit=dict(type='str'),
                provisioningpolicy=dict(type='str'),
                noprovisioningpolicy=dict(type='bool'),
                replicationpoollinkuid=dict(type='str'),
                resetreplicationpoollinkuid=dict(type='bool'),
                replication_partner_clusterid=dict(type='str'),
                warning=dict(type='int'),
                vdiskprotectionenabled=dict(type='str', choices=['yes', 'no']),
                ownershipgroup=dict(type='str'),
                noownershipgroup=dict(type='bool'),
                etfcmoverallocationmax=dict(type='str'),
                old_name=dict(type='str')
            )
        )

        mutually_exclusive = []
        self.module = AnsibleModule(argument_spec=argument_spec,
                                    mutually_exclusive=mutually_exclusive,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required
        self.name = self.module.params['name']
        self.state = self.module.params['state']

        # Optional
        self.datareduction = self.module.params.get('datareduction', None)
        self.easytier = self.module.params.get('easytier', None)
        self.encrypt = self.module.params.get('encrypt', None)
        self.ext = self.module.params.get('ext', None)
        self.safeguarded = self.module.params.get('safeguarded', False)
        self.noquota = self.module.params.get('noquota', False)
        self.provisioningpolicy = self.module.params.get('provisioningpolicy', '')
        self.noprovisioningpolicy = self.module.params.get('noprovisioningpolicy', False)
        self.replicationpoollinkuid = self.module.params.get('replicationpoollinkuid', '')
        self.resetreplicationpoollinkuid = self.module.params.get('resetreplicationpoollinkuid', False)
        self.replication_partner_clusterid = self.module.params.get('replication_partner_clusterid', '')
        self.warning = self.module.params.get('warning', None)
        self.ownershipgroup = self.module.params.get('ownershipgroup', '')
        self.noownershipgroup = self.module.params.get('noownershipgroup', False)
        self.vdiskprotectionenabled = self.module.params.get('vdiskprotectionenabled', None)
        self.etfcmoverallocationmax = self.module.params.get('etfcmoverallocationmax', '')
        self.old_name = self.module.params.get('old_name', '')

        self.parentmdiskgrp = self.module.params.get('parentmdiskgrp', None)
        self.size = self.module.params.get('size', None)
        self.unit = self.module.params.get('unit', None)

        # internal variable
        self.changed = False

        # Dynamic variable
        self.partnership_index = None

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
        if not self.name:
            self.module.fail_json(msg='Missing mandatory parameter: name')

        if self.state == 'present':
            message = 'Following parameters are required together: replicationpoollinkuid, replication_partner_clusterid'
            if self.replication_partner_clusterid:
                if not self.replicationpoollinkuid:
                    self.module.fail_json(msg=message)
            else:
                if self.replicationpoollinkuid:
                    self.module.fail_json(msg=message)

            if self.replicationpoollinkuid and self.resetreplicationpoollinkuid:
                self.module.fail_json(
                    msg='Mutually exclusive parameters: replicationpoollinkuid, resetreplicationpoollinkuid'
                )

        elif self.state == 'absent':
            invalids = ('datareduction', 'easytier', 'encrypt', 'ext', 'parentmdiskgrp',
                        'safeguarded', 'noquota', 'unit', 'provisioningpolicy', 'noprovisioningpolicy',
                        'replicationpoollinkuid', 'resetreplicationpoollinkuid', 'replication_partner_clusterid', 'size', 'warning',
                        'ownershipgroup', 'noownershipgroup', 'vdiskprotectionenabled', 'etfcmoverallocationmax', 'old_name')
            invalid_exists = ', '.join((var for var in invalids if getattr(self, var) not in {'', None, 'no', 'off'}))

            if invalid_exists:
                self.module.fail_json(
                    msg='state=absent but following parameters have been passed: {0}'.format(invalid_exists))

    def create_validation(self):
        invalids = ('noownershipgroup', 'old_name')
        invalid_exists = ', '.join((var for var in invalids if getattr(self, var) not in {'', None}))

        if invalid_exists:
            self.module.fail_json(
                msg='Following parameters not supported during creation: {0}'.format(invalid_exists)
            )

    def mdiskgrp_rename(self, mdiskgrp_data):
        msg = None
        old_mdiskgrp_data = self.mdiskgrp_exists(self.old_name)
        if not old_mdiskgrp_data and not mdiskgrp_data:
            self.module.fail_json(msg="mdiskgrp [{0}] does not exists.".format(self.old_name))
        elif old_mdiskgrp_data and mdiskgrp_data:
            self.module.fail_json(msg="mdiskgrp with name [{0}] already exists.".format(self.name))
        elif not old_mdiskgrp_data and mdiskgrp_data:
            msg = "mdiskgrp [{0}] already renamed.".format(self.name)
        elif old_mdiskgrp_data and not mdiskgrp_data:
            if (self.old_name == self.parentmdiskgrp):
                self.module.fail_json("Old name shouldn't be same as parentmdiskgrp while renaming childmdiskgrp")
            # when check_mode is enabled
            if self.module.check_mode:
                self.changed = True
                return
            self.restapi.svc_run_command('chmdiskgrp', {'name': self.name}, [self.old_name])
            self.changed = True
            msg = "mdiskgrp [{0}] has been successfully rename to [{1}].".format(self.old_name, self.name)
        return msg

    def mdiskgrp_exists(self, name):
        merged_result = {}
        data = self.restapi.svc_obj_info(
            cmd='lsmdiskgrp',
            cmdopts=None,
            cmdargs=['-gui', name]
        )

        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        return merged_result

    def mdiskgrp_create(self):
        # So ext is optional to mkmdiskgrp but make required in ansible
        # until all options for create are implemented.
        # if not self.ext:
        #    self.module.fail_json(msg="You must pass in ext to the module.")

        self.create_validation()

        self.log("creating mdisk group '%s'", self.name)

        # Make command
        cmd = 'mkmdiskgrp'
        cmdopts = {}

        if not self.ext:
            self.module.fail_json(msg="You must pass the ext to the module.")

        if self.noquota or self.safeguarded:
            if not self.parentmdiskgrp:
                self.module.fail_json(msg='Required parameter missing: parentmdiskgrp')

        self.check_partnership()

        if self.module.check_mode:
            self.changed = True
            return

        if self.parentmdiskgrp:
            cmdopts['parentmdiskgrp'] = self.parentmdiskgrp
            if self.size:
                cmdopts['size'] = self.size
            if self.unit:
                cmdopts['unit'] = self.unit
            if self.safeguarded:
                cmdopts['safeguarded'] = self.safeguarded
            if self.noquota:
                cmdopts['noquota'] = self.noquota
        else:
            if self.easytier:
                cmdopts['easytier'] = self.easytier
            if self.encrypt:
                cmdopts['encrypt'] = self.encrypt
            if self.ext:
                cmdopts['ext'] = str(self.ext)
        if self.provisioningpolicy:
            cmdopts['provisioningpolicy'] = self.provisioningpolicy
        if self.datareduction:
            cmdopts['datareduction'] = self.datareduction
        if self.replicationpoollinkuid:
            cmdopts['replicationpoollinkuid'] = self.replicationpoollinkuid
        if self.ownershipgroup:
            cmdopts['ownershipgroup'] = self.ownershipgroup
        if self.vdiskprotectionenabled:
            cmdopts['vdiskprotectionenabled'] = self.vdiskprotectionenabled
        if self.etfcmoverallocationmax:
            if "%" not in self.etfcmoverallocationmax and self.etfcmoverallocationmax != "off":
                cmdopts['etfcmoverallocationmax'] = self.etfcmoverallocationmax + "%"
            else:
                cmdopts['etfcmoverallocationmax'] = self.etfcmoverallocationmax

        if self.warning:
            cmdopts['warning'] = str(self.warning) + "%"
        cmdopts['name'] = self.name
        self.log("creating mdisk group command %s opts %s", cmd, cmdopts)

        # Run command
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log("creating mdisk group result %s", result)

        if self.replication_partner_clusterid:
            self.set_bit_mask()

        if 'message' in result:
            self.log("creating mdisk group command result message %s",
                     result['message'])
        else:
            self.module.fail_json(
                msg="Failed to create mdisk group [%s]" % (self.name))

    def check_partnership(self):
        if self.replication_partner_clusterid:
            merged_result = {}
            result = self.restapi.svc_obj_info(
                cmd='lspartnership',
                cmdopts=None,
                cmdargs=['-gui', self.replication_partner_clusterid]
            )

            if isinstance(result, list):
                for res in result:
                    merged_result = res
            else:
                merged_result = result

            if merged_result:
                self.partnership_index = merged_result.get('partnership_index')
            else:
                self.module.fail_json(
                    msg='Partnership does not exist for the given cluster ({0}).'.format(self.replication_partner_clusterid)
                )

    def set_bit_mask(self, systemmask=None):
        cmd = 'chmdiskgrp'
        bit_mask = '1'.ljust(int(self.partnership_index) + 1, '0') if not systemmask else systemmask
        cmdopts = {'replicationpoollinkedsystemsmask': bit_mask}
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=[self.name])

    def mdiskgrp_delete(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("deleting mdiskgrp '%s'", self.name)

        cmd = 'rmmdiskgrp'
        cmdopts = None
        cmdargs = [self.name]

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # chmkdiskgrp does not output anything when successful.

    def mdiskgrp_update(self, modify):
        # updte the mdisk group
        self.log("updating mdiskgrp '%s'", self.name)

        systemmask = None
        cmd = 'chmdiskgrp'

        if 'replicationpoollinkedsystemsmask' in modify:
            systemmask = modify.pop('replicationpoollinkedsystemsmask')

        if modify:
            cmdopts = modify
            self.restapi.svc_run_command(cmd, cmdopts, cmdargs=[self.name])

        if systemmask or 'replicationpoollinkuid' in modify:
            self.set_bit_mask(systemmask)

        self.changed = True

    def mdiskgrp_probe(self, data):
        props = {}

        field_mappings = (
            ('noprovisioningpolicy', not bool(data.get('provisioning_policy_name', ''))),
            ('provisioningpolicy', data.get('provisioning_policy_name', '')),
            ('noownershipgroup', not bool(data.get('owner_name', ''))),
            ('ownershipgroup', data.get('owner_name', '')),
            ('vdiskprotectionenabled', data.get('vdisk_protection_enabled', '')),
            ('replicationpoollinkuid', data.get('replication_pool_link_uid', '')),
        )

        for field, existing_value in field_mappings:
            new_value = getattr(self, field, None)
            if new_value is not None and new_value != existing_value:
                props[field] = getattr(self, field, None)

        if self.resetreplicationpoollinkuid:
            props['resetreplicationpoollinkuid'] = self.resetreplicationpoollinkuid
        if self.warning and self.warning != data.get('warning', ''):
            props['warning'] = str(self.warning) + "%"
        if self.etfcmoverallocationmax:
            if "%" not in self.etfcmoverallocationmax and self.etfcmoverallocationmax != "off":
                self.etfcmoverallocationmax += "%"
            if self.etfcmoverallocationmax != data.get('easy_tier_fcm_over_allocation_max', ''):
                props['etfcmoverallocationmax'] = self.etfcmoverallocationmax
        if self.replication_partner_clusterid:
            self.check_partnership()
            bit_mask = '1'.ljust(int(self.partnership_index) + 1, '0')
            if bit_mask.zfill(64) != data.get('replication_pool_linked_systems_mask', ''):
                props['replicationpoollinkedsystemsmask'] = bit_mask

        self.log("mdiskgrp_probe props='%s'", props)
        return props

    def apply(self):
        changed = False
        msg = None
        modify = []

        mdiskgrp_data = self.mdiskgrp_exists(self.name)
        if self.state == 'present' and self.old_name:
            msg = self.mdiskgrp_rename(mdiskgrp_data)
        elif self.state == 'absent' and self.old_name:
            self.module.fail_json(msg="Rename functionality is not supported when 'state' is absent.")

        else:
            if mdiskgrp_data:
                if self.state == 'absent':
                    self.log("CHANGED: mdisk group exists, "
                             "but requested state is 'absent'")
                    changed = True
                elif self.state == 'present':
                    # This is where we detect if chmdiskgrp should be called.
                    modify = self.mdiskgrp_probe(mdiskgrp_data)
                    if modify:
                        changed = True
            else:
                if self.state == 'present':
                    self.log("CHANGED: mdisk group does not exist, "
                             "but requested state is 'present'")
                    changed = True
            if changed:
                if self.state == 'present':
                    if not mdiskgrp_data:
                        self.mdiskgrp_create()
                        self.changed = True
                        msg = "Mdisk group [%s] has been created." % self.name
                    else:
                        # This is where we would modify
                        self.mdiskgrp_update(modify)
                        msg = "Mdisk group [%s] has been modified." % self.name

                elif self.state == 'absent':
                    self.mdiskgrp_delete()
                    self.changed = True
                    msg = "mdiskgrp [%s] has been deleted." % self.name

            else:
                self.log("exiting with no changes")
                if self.state == 'absent':
                    msg = "Mdisk group [%s] did not exist." % self.name
                else:
                    msg = "Mdisk group [%s] already exists. No modifications done" % self.name

        if self.module.check_mode:
            msg = 'skipping changes due to check mode'

        self.module.exit_json(msg=msg, changed=self.changed)


def main():
    v = IBMSVCmdiskgrp()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
