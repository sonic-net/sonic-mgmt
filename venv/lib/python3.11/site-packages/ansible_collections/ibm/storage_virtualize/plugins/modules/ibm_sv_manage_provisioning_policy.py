#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2022 IBM CORPORATION
# Author(s): Sanjaikumaar M <sanjaikumaar.m@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_sv_manage_provisioning_policy
short_description: This module configures and manages provisioning policies on IBM Storage Virtualize family systems
version_added: '1.10.0'
description:
  - Ansible interface to manage mkprovisioningpolicy, chprovisioningpolicy, and rmprovisioningpolicy commands.
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
            - Creates, updates (C(present)), or deletes (C(absent)) a provisioning policy.
        choices: [ present, absent ]
        required: true
        type: str
    name:
        description:
            - Specifies the name of the provisioning policy.
            - Specifies the new name during rename.
        type: str
        required: true
    capacitysaving:
        description:
            - Specifies the policy capacity savings.
            - Applies, when I(state=present), to create a provisioning policy.
        choices: [ drivebased, thin, compressed ]
        type: str
    deduplicated:
        description:
            - Specifies when volumes should be deduplicated.
            - Applicable when I(capacitysaving=thin) or I(capacitysaving=compressed).
        default: false
        type: bool
    old_name:
        description:
            - Specifies the old name of the provisioning policy during renaming.
            - Valid when I(state=present) to rename an existing policy.
        type: str
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
author:
    - Sanjaikumaar M (@sanjaikumaar)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create provisioning policy
  ibm.storage_virtualize.ibm_sv_manage_provisioning_policy:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: provisioning_policy0
    capacitysaving: "compressed"
    deduplicated: true
    state: present
- name: Rename provisioning policy
  ibm.storage_virtualize.ibm_sv_manage_provisioning_policy:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: pp0
    old_name: provisioning_policy0
    state: present
- name: Delete replication policy
  ibm.storage_virtualize.ibm_sv_manage_provisioning_policy:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: pp0
    state: absent
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (
    IBMSVCRestApi, svc_argument_spec,
    get_logger, strtobool
)
from ansible.module_utils._text import to_native


class IBMSVProvisioningPolicy:

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
                capacitysaving=dict(
                    type='str',
                    choices=['drivebased', 'thin', 'compressed']
                ),
                deduplicated=dict(
                    type='bool',
                    default=False
                ),
                old_name=dict(
                    type='str',
                ),
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # Required parameters
        self.name = self.module.params['name']
        self.state = self.module.params['state']

        # Optional parameters
        self.capacitysaving = self.module.params.get('capacitysaving')
        self.deduplicated = self.module.params.get('deduplicated', False)
        self.old_name = self.module.params.get('old_name', '')

        self.basic_checks()

        # logging setup
        self.log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, self.log_path)
        self.log = log.info

        # Dynamic variables
        self.changed = False
        self.msg = ''
        self.pp_data = {}

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
            if not self.name:
                self.module.fail_json(
                    msg='Mandatory parameter missing: name'
                )
        else:
            unsupported = ('capacitysaving', 'deduplicated', 'old_name')
            unsupported_exists = ','.join(field for field in unsupported if getattr(self, field))
            if unsupported_exists:
                self.module.fail_json(
                    msg='state=absent but following parameters passed: {0}'.format(unsupported_exists)
                )

    def create_validation(self):
        if self.old_name:
            self.rename_validation([])

        if not self.capacitysaving:
            self.module.fail_json(
                msg='Mandatory parameter missing: capacitysaving'
            )

    def rename_validation(self, updates):
        if self.old_name and self.name:
            if self.name == self.old_name:
                self.module.fail_json(msg='New name and old name should be different.')

            new = self.is_pp_exists()
            existing = self.is_pp_exists(name=self.old_name)

            if existing:
                if new:
                    self.module.fail_json(
                        msg='Provisioning policy ({0}) already exists for the given new name'.format(self.name)
                    )
                else:
                    updates.append('name')
            else:
                if not new:
                    self.module.fail_json(
                        msg='Provisioning policy ({0}) does not exists for the given old name.'.format(self.old_name)
                    )
                else:
                    self.module.exit_json(
                        msg='Provisioning policy ({0}) already renamed. No modifications done.'.format(self.name)
                    )

    def is_pp_exists(self, name=None):
        result = {}
        name = name if name else self.name
        cmd = 'lsprovisioningpolicy'
        data = self.restapi.svc_obj_info(cmd=cmd, cmdopts=None, cmdargs=[name])

        if isinstance(data, list):
            for d in data:
                result.update(d)
        else:
            result = data

        self.pp_data = result

        return result

    def create_provisioning_policy(self):
        self.create_validation()
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'mkprovisioningpolicy'
        cmdopts = {
            'name': self.name,
            'capacitysaving': self.capacitysaving,
            'deduplicated': self.deduplicated
        }

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log('Provisioning policy (%s) created', self.name)
        self.changed = True

    def provisioning_policy_probe(self):
        updates = []
        self.rename_validation(updates)
        if self.capacitysaving:
            capsav = 'none' if self.capacitysaving == 'drivebased' else self.capacitysaving
            if capsav and capsav != self.pp_data.get('capacity_saving', ''):
                self.module.fail_json(msg='Following parameter not applicable for update operation: capacitysaving')
        if self.deduplicated and not strtobool(self.pp_data.get('deduplicated', 0)):
            self.module.fail_json(msg='Following parameter not applicable for update operation: deduplicated')
        return updates

    def update_provisioning_policy(self, updates):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'chprovisioningpolicy'
        cmdopts = {
            'name': self.name
        }
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=[self.old_name])
        self.log('Provisioning policy (%s) renamed', self.name)
        self.changed = True

    def delete_provisioning_policy(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'rmprovisioningpolicy'
        self.restapi.svc_run_command(cmd, cmdopts=None, cmdargs=[self.name])
        self.changed = True

    def apply(self):
        if self.is_pp_exists(name=self.old_name):
            if self.state == 'present':
                modifications = self.provisioning_policy_probe()
                if any(modifications):
                    self.update_provisioning_policy(modifications)
                    self.msg = 'Provisioning policy ({0}) updated'.format(self.name)
                else:
                    self.msg = 'Provisioning policy ({0}) already exists. No modifications done.'.format(self.name)
            else:
                self.delete_provisioning_policy()
                self.msg = 'Provisioning policy ({0}) deleted'.format(self.name)
        else:
            if self.state == 'absent':
                self.msg = 'Provisioning policy ({0}) does not exist.'.format(self.name)
            else:
                self.create_provisioning_policy()
                self.msg = 'Provisioning policy ({0}) created.'.format(self.name)

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'

        self.module.exit_json(
            changed=self.changed,
            msg=self.msg
        )


def main():
    v = IBMSVProvisioningPolicy()
    try:
        v.apply()
    except Exception as e:
        v.log('Exception in apply(): \n%s', format_exc())
        v.module.fail_json(msg='Module failed. Error [%s].' % to_native(e))


if __name__ == '__main__':
    main()
