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
module: ibm_sv_restore_cloud_backup
short_description: This module restores the cloud backup on IBM Storage Virtualize family systems
version_added: '1.11.0'
description:
  - Ansible interface to manage restorevolume command.
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
    target_volume_name:
        description:
            - Specifies the volume name to restore onto.
        type: str
        required: true
    source_volume_uid:
        description:
            - Specifies the volume snapshot to restore (specified by volume UID).
            - This parameter is required to restore a backup from a different volume.
            - Specified UID must be different from the UID of the volume being restored.
        type: str
    generation:
        description:
            - Specifies the snapshot generation to restore. The value must be a number.
        type: int
    restoreuid:
        description:
            - Specifies the UID of the restored volume should be set to the UID
              of the volume snapshot that is being restored.
            - This parameter can be used only with I(source_volume_uid).
            - The I(restoreuid) parameter is not supported if cloud account is in import mode.
        type: bool
    deletelatergenerations:
        description:
            - Specifies that all backup generations should be deleted after the generation is restored.
        type: bool
    cancel:
        description:
            - Specifies to cancel the restore operation.
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
- name: Restore cloud backup
  ibm.storage_virtualize.ibm_sv_restore_cloud_backup:
    clustername: "{{ cluster_A }}"
    username: "{{ username_A }}"
    password: "{{ password_A }}"
    target_volume_name: vol1
    source_volume_uid: 6005076400B70038E00000000000001C
    generation: 1
- name: Restore cloud backup to different cluster
  ibm.storage_virtualize.ibm_sv_restore_cloud_backup:
    clustername: "{{ cluster_B }}"
    username: "{{ username_B }}"
    password: "{{ password_B }}"
    target_volume_name: vol2
    source_volume_uid: 6005076400B70038E00000000000001C
    generation: 1
- name: Cancel restore operation
  ibm.storage_virtualize.ibm_sv_restore_cloud_backup:
    clustername: "{{ cluster_A }}"
    username: "{{ username_A }}"
    password: "{{ password_A }}"
    target_volume_name: vol1
    cancel: true
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (
    IBMSVCRestApi, svc_argument_spec,
    get_logger
)
from ansible.module_utils._text import to_native


class IBMSVRestoreCloudBackup:

    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                target_volume_name=dict(
                    type='str',
                    required=True
                ),
                source_volume_uid=dict(
                    type='str'
                ),
                generation=dict(
                    type='int',
                ),
                restoreuid=dict(
                    type='bool'
                ),
                deletelatergenerations=dict(
                    type='bool'
                ),
                cancel=dict(
                    type='bool'
                ),
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # Required parameters
        self.target_volume_name = self.module.params.get('target_volume_name', '')
        self.source_volume_uid = self.module.params.get('source_volume_uid', '')
        self.generation = self.module.params.get('generation', '')
        self.restoreuid = self.module.params.get('restoreuid', '')
        self.deletelatergenerations = self.module.params.get('deletelatergenerations', False)
        self.cancel = self.module.params.get('cancel', False)

        self.basic_checks()

        # logging setup
        self.log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, self.log_path)
        self.log = log.info

        # Dynamic variables
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
        if not self.target_volume_name:
            self.module.fail_json(msg='Missing mandatory parameter: target_volume_name')

        if self.cancel:
            invalids = ('source_volume_uid', 'generation', 'restoreuid', 'deletelatergenerations')
            invalid_exists = ', '.join((var for var in invalids if getattr(self, var) not in {'', None}))

            if invalid_exists:
                self.module.fail_json(
                    msg='Parameters not supported during restore cancellation: {0}'.format(invalid_exists)
                )

    def validate(self):
        if not self.cancel:
            cmd = 'lsvolumebackupgeneration'
            cmdargs = None
            cmdopts = {}

            if self.source_volume_uid:
                cmdopts['uid'] = self.source_volume_uid
            else:
                cmdopts['volume'] = self.target_volume_name

            result = self.restapi.svc_obj_info(cmd=cmd, cmdopts=cmdopts, cmdargs=cmdargs)
        else:
            result = True
            cmd = 'lsvdisk'
            vdata = {}
            data = self.restapi.svc_obj_info(cmd=cmd, cmdopts=None, cmdargs=[self.target_volume_name])

            if isinstance(data, list):
                for d in data:
                    vdata.update(d)
            else:
                vdata = data

            if vdata and self.cancel and vdata['restore_status'] in {'none', 'available'}:
                self.module.exit_json(
                    msg='No restore operation is in progress for the volume ({0}).'.format(self.target_volume_name)
                )

        return result

    def restore_volume(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'restorevolume'
        cmdargs = [self.target_volume_name]
        cmdopts = {}

        if self.cancel:
            cmdopts['cancel'] = self.cancel
            self.msg = 'Restore operation on volume ({0}) cancelled.'.format(self.target_volume_name)
        else:
            if self.source_volume_uid:
                cmdopts['fromuid'] = self.source_volume_uid

            if self.generation:
                cmdopts['generation'] = self.generation

            if self.restoreuid:
                cmdopts['restoreuid'] = self.restoreuid

            if self.deletelatergenerations:
                cmdopts['deletelatergenerations'] = self.deletelatergenerations

            self.msg = 'Restore operation on volume ({0}) started.'.format(self.target_volume_name)

        response = self.restapi._svc_token_wrap(cmd, cmdopts, cmdargs=cmdargs)
        self.log('response=%s', response)
        self.changed = True

        if response['out']:
            if b'CMMVC9103E' in response['out']:
                self.msg = 'CMMVC9103E: Volume ({0}) is not ready to perform any operation right now.'.format(
                    self.target_volume_name
                )
                self.changed = False
            elif b'CMMVC9099E' in response['out']:
                self.msg = 'No restore operation is in progress for the volume ({0}).'.format(self.target_volume_name)
                self.changed = False
            else:
                self.module.fail_json(msg=response)

    def apply(self):
        if self.validate():
            self.restore_volume()
            self.log(self.msg)
        else:
            self.msg = 'No backup exist for the given source UID/volume.'
            self.log(self.msg)
            self.module.fail_json(msg=self.msg)

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'
            self.log(self.msg)

        self.module.exit_json(
            changed=self.changed,
            msg=self.msg
        )


def main():
    v = IBMSVRestoreCloudBackup()
    try:
        v.apply()
    except Exception as e:
        v.log('Exception in apply(): \n%s', format_exc())
        v.module.fail_json(msg='Module failed. Error [%s].' % to_native(e))


if __name__ == '__main__':
    main()
