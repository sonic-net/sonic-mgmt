#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2023 IBM CORPORATION
# Author(s): Sanjaikumaar M <sanjaikumaar.m@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_sv_manage_fc_partnership
short_description: This module configures and manages Fibre Channel (FC) partnership on IBM Storage Virtualize family systems
version_added: '1.12.0'
description:
  - Ansible interface to manage mkfcpartnership, chpartnership, and rmpartnership commands.
options:
    state:
        description:
            - Creates or updates (C(present)) or removes (C(absent)) a FC partnership.
        choices: [ 'present', 'absent' ]
        required: true
        type: str
    clustername:
        description:
            - The hostname or management IP of the Storage Virtualize system.
        type: str
        required: true
    remote_clustername:
        description:
            - The hostname or management IP of the remote Storage Virtualize system.
        type: str
    domain:
        description:
            - Domain for the Storage Virtualize system.
            - Valid when hostname is used for the parameter I(clustername).
        type: str
    remote_domain:
        description:
            - Domain for the remote Storage Virtualize system.
            - Valid when hostname is used for the parameter I(remote_clustername).
        type: str
    username:
        description:
            - REST API username for the Storage Virtualize system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    remote_username:
        description:
            - REST API username for the remote Storage Virtualize system.
            - The parameters I(remote_username) and I(remote_password) are required if not using I(remote_token) to authenticate a user.
        type: str
    password:
        description:
            - REST API password for the Storage Virtualize system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    remote_password:
        description:
            - REST API password for the remote Storage Virtualize system.
            - The parameters I(remote_username) and I(remote_password) are required if not using I(remote_token) to authenticate a user.
        type: str
    token:
        description:
            - The authentication token to verify a user on the Storage Virtualize system.
            - To generate a token, use the M(ibm.storage_virtualize.ibm_svc_auth) module.
        type: str
    remote_token:
        description:
            - The authentication token to verify a user on the remote Storage Virtualize system.
            - To generate a token, use the M(ibm.storage_virtualize.ibm_svc_auth) module.
        type: str
    remote_system:
        description:
            - Specifies the partner system ID or name.
        type: str
    linkbandwidthmbits:
        description:
            - Specifies the aggregate bandwidth of the remote copy link between two clustered systems (systems)
              in megabits per second (Mbps). The value must be in the range of 1 - 100000.
            - Valid when I(state=present).
        type: str
    backgroundcopyrate:
        description:
            - Specifies the maximum percentage of aggregate link bandwidth that can be used for background
              copy operations. The value must be in the range of 0 - 100. The default value is 50.
            - Valid when I(state=present).
        type: str
    pbrinuse:
        description:
            - Specifies whether policy-based replication will be used on the partnership.
            - Valid when I(state=present) to update a partnership.
        type: str
        choices: [ 'yes', 'no' ]
    start:
        description:
            - Specifies to start a partnership.
            - Valid when I(state=present).
        type: bool
    stop:
        description:
            - Specifies to stop a partnership.
            - Valid when I(state=present) to update a partnership.
        type: bool
    validate_certs:
        description:
            - Validates certification for the local Storage Virtualize system.
        default: false
        type: bool
    remote_validate_certs:
        description:
            - Validates certification for the remote Storage Virtualize system.
        default: false
        type: bool
    log_path:
        description:
            - Path of debug log file.
        type: str
author:
    - Sanjaikumaar M (@sanjaikumaar)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create an FC partnership and start the partnership
  ibm.storage_virtualize.ibm_sv_manage_fc_partnership:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    remote_clustername: "{{ remote_clustername }}"
    remote_username: "{{ remote_username }}"
    remote_password: "{{ remote_password }}"
    remote_system: "{{ remote_system }}"
    linkbandwidthmbits: 50
    backgroundcopyrate: 50
    start: 'True'
    state: present
- name: Update an FC partnership and stop the partnership
  ibm.storage_virtualize.ibm_sv_manage_fc_partnership:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    remote_clustername: "{{ remote_clustername }}"
    remote_username: "{{ remote_username }}"
    remote_password: "{{ remote_password }}"
    remote_system: "{{ remote_system }}"
    linkbandwidthmbits: 40
    backgroundcopyrate: 20
    stop: 'True'
    state: present
- name: Delete the FC partnership
  ibm.storage_virtualize.ibm_sv_manage_fc_partnership:
    clustername: "{{ cluster }}"
    username: "{{ username }}"
    password: "{{ password }}"
    remote_clustername: "{{ remote_clustername }}"
    remote_username: "{{ remote_username }}"
    remote_password: "{{ remote_password }}"
    remote_system: "{{ remote_system }}"
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


class IBMSVFCPartnership:

    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                state=dict(type='str', required=True, choices=['present', 'absent']),
                remote_system=dict(type='str'),
                linkbandwidthmbits=dict(type='str'),
                backgroundcopyrate=dict(type='str'),
                remote_clustername=dict(type='str'),
                remote_domain=dict(type='str', default=None),
                remote_username=dict(type='str'),
                remote_password=dict(type='str', no_log=True),
                remote_token=dict(type='str', no_log=True),
                remote_validate_certs=dict(type='bool', default=False),
                pbrinuse=dict(type='str', choices=['yes', 'no']),
                start=dict(type='bool'),
                stop=dict(type='bool')
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # Required
        self.state = self.module.params['state']
        self.remote_system = self.module.params['remote_system']

        # Optional
        self.linkbandwidthmbits = self.module.params.get('linkbandwidthmbits', '')
        self.backgroundcopyrate = self.module.params.get('backgroundcopyrate', '')
        self.start = self.module.params.get('start', '')
        self.stop = self.module.params.get('stop', '')
        self.pbrinuse = self.module.params.get('pbrinuse', '')
        self.remote_clustername = self.module.params.get('remote_clustername', '')
        self.remote_username = self.module.params.get('remote_username', '')
        self.remote_password = self.module.params.get('remote_password', '')
        self.remote_domain = self.module.params.get('remote_domain', '')
        self.remote_token = self.module.params.get('remote_token', '')
        self.remote_validate_certs = self.module.params.get('remote_validate_certs', '')

        self.basic_checks()

        # logging setup
        self.log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, self.log_path)
        self.log = log.info

        # Dynamic variables
        self.changed = False
        self.msg = ''
        self.local_id = None
        self.partnership_data = None

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

        if self.remote_clustername:
            self.remote_restapi = IBMSVCRestApi(
                module=self.module,
                clustername=self.remote_clustername,
                domain=self.remote_domain,
                username=self.remote_username,
                password=self.remote_password,
                validate_certs=self.remote_validate_certs,
                log_path=self.log_path,
                token=self.remote_token
            )

    def basic_checks(self):
        if not self.remote_system:
            self.module.fail_json(msg='Missing mandatory parameter: remote_system')

        if self.state == 'present':
            if self.start and self.stop:
                self.module.fail_json(msg='Mutually exclusive parameters: start, stop')
        else:
            invalids = ('linkbandwidthmbits', 'backgroundcopyrate', 'start', 'stop', 'pbrinuse')
            invalid_exists = ', '.join((var for var in invalids if getattr(self, var) not in {'', None}))
            if invalid_exists:
                self.module.fail_json(
                    msg='Following parameters not supported during deletion: {0}'.format(invalid_exists)
                )

    def create_validation(self, validate):
        if validate:
            if not self.remote_clustername:
                self.module.fail_json(msg='Following parameter is mandatory during creation: remote_clustername')

            if not self.linkbandwidthmbits:
                self.module.fail_json(msg='Missing mandatory parameter: linkbandwidthmbits')

            invalids = ('stop', 'pbrinuse')
            invalid_exists = ', '.join((var for var in invalids if getattr(self, var) not in {'', None}))
            if invalid_exists:
                self.module.fail_json(
                    msg='Following parameters not supported during creation: {0}'.format(invalid_exists)
                )

    def is_partnership_exists(self, restapi, cluster):
        result = {}
        data = restapi.svc_obj_info(
            cmd='lspartnership',
            cmdopts=None,
            cmdargs=[cluster]
        )

        if isinstance(data, list):
            for d in data:
                result.update(d)
        else:
            result = data

        self.partnership_data = result

        return result

    def create_fc_partnership(self, restapi, cluster, validate):
        self.create_validation(validate)
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'mkfcpartnership'
        cmdopts = {
            'linkbandwidthmbits': self.linkbandwidthmbits
        }

        if self.backgroundcopyrate:
            cmdopts['backgroundcopyrate'] = self.backgroundcopyrate

        restapi.svc_run_command(cmd, cmdopts, cmdargs=[cluster])
        self.log('FC partnership (%s) created', cluster)

        if self.start:
            restapi.svc_run_command('chpartnership', {'start': True}, [cluster])
            self.log('FC partnership (%s) started', cluster)

        self.changed = True

    def probe_fc_partnership(self):
        probe_data = {}
        if self.linkbandwidthmbits and self.linkbandwidthmbits != self.partnership_data.get('link_bandwidth_mbits'):
            probe_data['linkbandwidthmbits'] = self.linkbandwidthmbits

        if self.backgroundcopyrate and self.backgroundcopyrate != self.partnership_data.get('background_copy_rate'):
            probe_data['backgroundcopyrate'] = self.backgroundcopyrate

        if self.pbrinuse and self.pbrinuse != self.partnership_data.get('pbr_in_use'):
            probe_data['pbrinuse'] = self.pbrinuse

        if self.start in {True, False}:
            probe_data['start'] = self.start

        if self.stop in {True, False}:
            probe_data['stop'] = self.stop

        return probe_data

    def updated_fc_partnership(self, modification, restapi, cluster):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'chpartnership'
        if 'start' in modification:
            modification.pop('start')
            restapi.svc_run_command(cmd, {'start': True}, [cluster])
            self.changed = True

        if 'stop' in modification:
            modification.pop('stop')
            restapi.svc_run_command(cmd, {'stop': True}, [cluster])
            self.changed = True

        if modification:
            restapi.svc_run_command(cmd, modification, [cluster])
            self.changed = True

    def delete_fc_partnership(self, restapi, cluster):
        if self.module.check_mode:
            self.changed = True
            return

        restapi.svc_run_command('rmpartnership', None, [cluster])
        self.changed = True

    def apply(self):
        subset = [(self.restapi, self.remote_system, True)]
        if self.remote_clustername:
            system_data = self.restapi.svc_obj_info('lssystem', None, None)
            self.local_id = system_data['id']
            subset.append((self.remote_restapi, self.local_id, False))

        for restapi, cluster, validate in subset:
            if self.is_partnership_exists(restapi, cluster):
                if self.state == 'present':
                    modifications = self.probe_fc_partnership()
                    if modifications:
                        self.updated_fc_partnership(modifications, restapi, cluster)
                        self.msg += 'FC partnership ({0}) updated. '.format(cluster)
                    else:
                        self.msg += 'FC partnership ({0}) already exists. No modifications done. '.format(cluster)
                else:
                    self.delete_fc_partnership(restapi, cluster)
                    self.msg += 'FC partnership ({0}) deleted. '.format(cluster)
            else:
                if self.state == 'absent':
                    self.msg += 'FC partnership ({0}) does not exist. No modifications done. '.format(cluster)
                else:
                    self.create_fc_partnership(restapi, cluster, validate)
                    self.msg += 'FC partnership to the cluster({0}) created. '.format(cluster)

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'
            self.log(self.msg)

        self.module.exit_json(
            changed=self.changed,
            msg=self.msg
        )


def main():
    v = IBMSVFCPartnership()
    try:
        v.apply()
    except Exception as e:
        v.log('Exception in apply(): \n%s', format_exc())
        v.module.fail_json(msg='Module failed. Error [%s].' % to_native(e))


if __name__ == '__main__':
    main()
