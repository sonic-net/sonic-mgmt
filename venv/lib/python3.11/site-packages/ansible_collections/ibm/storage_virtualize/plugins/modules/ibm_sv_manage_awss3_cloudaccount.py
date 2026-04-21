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
module: ibm_sv_manage_awss3_cloudaccount
short_description: This module configures and manages Amazon Simple Storage Service (Amazon S3) cloud account on IBM Storage Virtualize family systems
version_added: '1.11.0'
description:
  - Ansible interface to manage mkcloudaccountawss3, chcloudaccountawss3, and rmcloudaccount commands.
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
            - Creates, updates (C(present)), or deletes (C(absent)) an Amazon S3 account.
        choices: [ present, absent ]
        required: true
        type: str
    name:
        description:
            - Specifies the name of an Amazon S3 account.
        type: str
        required: true
    old_name:
        description:
            - Specifies the old name of an Amazon S3 account.
            - Valid when I(state=present), to rename the existing Amazon S3 account.
        type: str
    bucketprefix:
        description:
            - Specifies the prefix for the bucket object.
            - Applies, when I(state=present), to create an Amazon S3 account.
        type: str
    accesskeyid:
        description:
            - Specifies the public part of the Amazon S3 access key credential
              of the AWS user that the system use to access the cloud storage.
        type: str
    secretaccesskey:
        description:
            - Specifies the secret access key of an Amazon S3 cloud account.
        type: str
    upbandwidthmbits:
        description:
            - Specifies the upload bandwidth limit in megabits per second (Mbps).
            - The value must be a number 1-10240.
        type: str
    downbandwidthmbits:
        description:
            - Specifies the download bandwidth limit in megabits per second (Mbps).
            - The value must be a number 1-10240.
        type: str
    region:
        description:
            - Specifies the AWS region to use to access the cloud account and store data.
        type: str
    encrypt:
        description:
            - Specifies whether to encrypt the data in the cloud account.
            - By default, encryption is enabled if encryption is enabled on
              the cluster unless I(encrypt=no) is specified.
            - Valid when I(state=present) to create an Amazon S3 account.
        type: str
        choices: [ 'yes', 'no' ]
    ignorefailures:
        description:
            - Specify to change the access key whether the new access key works or not.
            - Valid when I(state=present) to update an existing Amazon S3 account.
            - Parameter is allowed only when I(accesskeyid) and I(secretaccesskey) are entered.
        type: bool
    mode:
        description:
            - Specifies the new or modified cloud account mode.
            - Valid when I(state=present) to update an existing Amazon S3 account.
        type: str
        choices: [ import, normal ]
    importsystem:
        description:
            - Specifies that the system's data be imported.
            - Valid when I(state=present) to update an existing Amazon S3 account.
        type: str
    refresh:
        description:
            - Specifies a refresh of the system import candidates.
            - If the account is in import mode, this parameter specifies a refresh of the data available for import.
        type: bool
    resetusagehistory:
        description:
            - Resets the usage history (to 0).
            - Storage consumption that reflects the space that is consumed on the cloud account is cumulative,
              which means that it remains in the current day row (the 0th row).
            - Valid when I(state=present) to update an existing Amazon S3 account.
        type: bool
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
- name: Configure Amazon S3 account
  ibm.storage_virtualize.ibm_sv_manage_awss3_cloudaccount:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: awss3
    bucketprefix: "{{ bucketprefix }}"
    accesskeyid: "{{ accesskeyid }}"
    secretaccesskey: "{{ secretaccesskey }}"
    state: present
- name: Update Amazon S3 account configuration
  ibm.storage_virtualize.ibm_sv_manage_awss3_cloudaccount:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: awss3
    upbandwidthmbits: "{{ upbandwidthmbits }}"
    downbandwidthmbits: "{{ downbandwidthmbits }}"
    state: present
- name: Update Amazon S3 account mode to import
  ibm.storage_virtualize.ibm_sv_manage_awss3_cloudaccount:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: awss3
    mode: import
    importsystem: 123456789
    state: present
- name: Delete Amazon S3 account configuration
  ibm.storage_virtualize.ibm_sv_manage_awss3_cloudaccount:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: awss3
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


class IBMSVAWSS3:

    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                state=dict(
                    type='str',
                    choices=['present', 'absent'],
                    required=True
                ),
                name=dict(
                    type='str',
                    required=True
                ),
                old_name=dict(
                    type='str'
                ),
                bucketprefix=dict(
                    type='str',
                ),
                accesskeyid=dict(
                    type='str',
                    no_log=False
                ),
                secretaccesskey=dict(
                    type='str',
                    no_log=True
                ),
                upbandwidthmbits=dict(
                    type='str'
                ),
                downbandwidthmbits=dict(
                    type='str'
                ),
                region=dict(
                    type='str'
                ),
                encrypt=dict(
                    type='str',
                    choices=['yes', 'no']
                ),
                ignorefailures=dict(
                    type='bool'
                ),
                mode=dict(
                    type='str',
                    choices=['import', 'normal']
                ),
                importsystem=dict(
                    type='str'
                ),
                refresh=dict(
                    type='bool'
                ),
                resetusagehistory=dict(
                    type='bool'
                ),
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # Required parameters
        self.state = self.module.params.get('state')
        self.name = self.module.params.get('name')
        self.old_name = self.module.params.get('old_name', '')
        self.bucketprefix = self.module.params.get('bucketprefix', '')
        self.accesskeyid = self.module.params.get('accesskeyid', '')
        self.secretaccesskey = self.module.params.get('secretaccesskey')
        self.upbandwidthmbits = self.module.params.get('upbandwidthmbits', '')
        self.downbandwidthmbits = self.module.params.get('downbandwidthmbits', '')
        self.region = self.module.params.get('region', '')
        self.encrypt = self.module.params.get('encrypt')
        # ignorefailures will be allowed only when access and secretkey are entered
        self.ignorefailures = self.module.params.get('ignorefailures')
        self.mode = self.module.params.get('mode')
        self.importsystem = self.module.params.get('importsystem')
        self.refresh = self.module.params.get('refresh')
        self.resetusagehistory = self.module.params.get('resetusagehistory')

        self.basic_checks()

        # logging setup
        self.log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, self.log_path)
        self.log = log.info

        # Dynamic variables
        self.changed = False
        self.msg = ''
        self.aws_data = {}

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
            self.module.fail_json(msg='Missing mandatory parameter: name')

        if self.state == 'present':
            if self.accesskeyid:
                if not self.secretaccesskey:
                    self.module.fail_json(msg='Parameters required together: accesskeyid, secretaccesskey')

        elif self.state == 'absent':
            invalids = ('bucketprefix', 'accesskeyid', 'secretaccesskey', 'upbandwidthmbits',
                        'downbandwidthmbits', 'region', 'encrypt', 'ignorefailures', 'mode', 'importsystem',
                        'refresh', 'resetusagehistory', 'old_name')
            invalid_exists = ', '.join((var for var in invalids if getattr(self, var) not in {'', None}))

            if invalid_exists:
                self.module.fail_json(
                    msg='state=absent but following parameters have been passed: {0}'.format(invalid_exists)
                )

    def create_validation(self):
        if self.old_name:
            self.rename_validation({})

        required = ('bucketprefix', 'accesskeyid', 'secretaccesskey')
        required_not_exists = ', '.join((var for var in required if not getattr(self, var)))

        if required_not_exists:
            self.module.fail_json(msg='Missing mandatory parameter: {0}'.format(required_not_exists))

        invalids = ('ignorefailures', 'mode', 'importsystem',
                    'refresh', 'resetusagehistory')
        invalid_exists = ', '.join((var for var in invalids if getattr(self, var) not in {'', None}))

        if invalid_exists:
            self.module.fail_json(
                msg='Following parameters not supported during creation: {0}'.format(invalid_exists)
            )

    def rename_validation(self, updates):
        if self.old_name and self.name:

            if self.name == self.old_name:
                self.module.fail_json(msg='New name and old name should be different.')

            new = self.is_aws_account_exists()
            existing = self.is_aws_account_exists(name=self.old_name)

            if existing:
                if new:
                    self.module.fail_json(
                        msg='Cloud account ({0}) already exists for the given new name.'.format(self.name)
                    )
                else:
                    updates['name'] = self.name
            else:
                if not new:
                    self.module.fail_json(
                        msg='Cloud account ({0}) does not exists for the given old name.'.format(self.old_name)
                    )
                else:
                    self.module.exit_json(
                        msg='Cloud account ({0}) already renamed. No modifications done.'.format(self.name)
                    )

    def is_aws_account_exists(self, name=None):
        result = {}
        cmd = 'lscloudaccount'
        name = name if name else self.name

        data = self.restapi.svc_obj_info(cmd=cmd, cmdopts=None, cmdargs=[name])
        if isinstance(data, list):
            for d in data:
                result.update(d)
        else:
            result = data

        self.aws_data = result

        return result

    def aws_account_probe(self):
        updates = {}
        if self.encrypt and self.encrypt != self.aws_data.get('encrypt', ''):
            self.module.fail_json(msg='Parameter not supported for update operation: encrypt')

        if self.bucketprefix and self.bucketprefix != self.aws_data.get('awss3_bucket_prefix', ''):
            self.module.fail_json(msg='Parameter not supported for update operation: bucketprefix')

        if self.region and self.region != self.aws_data.get('awss3_region', ''):
            self.module.fail_json(msg='Parameter not supported for update operation: region')

        self.rename_validation(updates)

        params = [
            ('upbandwidthmbits', self.aws_data.get('up_bandwidth_mbits')),
            ('downbandwidthmbits', self.aws_data.get('down_bandwidth_mbits')),
            ('mode', self.aws_data.get('mode')),
            ('importsystem', self.aws_data.get('import_system_name')),
        ]

        for k, v in params:
            if getattr(self, k) and getattr(self, k) != v:
                updates[k] = getattr(self, k)

        if self.accesskeyid and self.aws_data.get('awss3_access_key_id') != self.accesskeyid:
            updates['accesskeyid'] = self.accesskeyid
            updates['secretaccesskey'] = self.secretaccesskey

            # ignorefailures can be provided only when accesskeyid and secretaccesskey are given
            if self.ignorefailures:
                updates['ignorefailures'] = self.ignorefailures

        if self.refresh and self.aws_data.get('refreshing') == 'no':
            updates['refresh'] = self.refresh

        # Can't validate the below parameters.
        if self.resetusagehistory:
            updates['resetusagehistory'] = self.resetusagehistory

        return updates

    def create_aws_account(self):
        self.create_validation()
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'mkcloudaccountawss3'
        cmdopts = {
            'name': self.name,
            'bucketprefix': self.bucketprefix,
            'accesskeyid': self.accesskeyid,
            'secretaccesskey': self.secretaccesskey
        }

        params = {'upbandwidthmbits', 'downbandwidthmbits', 'region', 'encrypt'}

        cmdopts.update(
            dict((key, getattr(self, key)) for key in params if getattr(self, key))
        )

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None, timeout=20)
        self.log('Cloud account (%s) created', self.name)
        self.changed = True

    def update_aws_account(self, updates):
        if self.module.check_mode:
            self.changed = True
            return

        name = self.old_name if self.old_name else self.name
        self.restapi.svc_run_command('chcloudaccountawss3', updates, cmdargs=[name], timeout=20)
        self.changed = True

    def delete_aws_account(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.restapi.svc_run_command('rmcloudaccount', cmdopts=None, cmdargs=[self.name], timeout=20)
        self.changed = True

    def apply(self):
        if self.is_aws_account_exists(name=self.old_name):
            if self.state == 'present':
                modifications = self.aws_account_probe()
                if modifications:
                    self.update_aws_account(modifications)
                    self.msg = 'AWS account ({0}) updated'.format(self.name)
                else:
                    self.msg = 'AWS account ({0}) already exists. No modifications done.'.format(self.name)
            else:
                self.delete_aws_account()
                self.msg = 'AWS account ({0}) deleted.'.format(self.name)
        else:
            if self.state == 'absent':
                self.msg = 'AWS account ({0}) does not exist'.format(self.name)
            else:
                self.create_aws_account()
                self.msg = 'AWS account ({0}) created.'.format(self.name)

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'

        self.module.exit_json(
            changed=self.changed,
            msg=self.msg
        )


def main():
    v = IBMSVAWSS3()
    try:
        v.apply()
    except Exception as e:
        v.log('Exception in apply(): \n%s', format_exc())
        v.module.fail_json(msg='Module failed. Error [%s].' % to_native(e))


if __name__ == '__main__':
    main()
