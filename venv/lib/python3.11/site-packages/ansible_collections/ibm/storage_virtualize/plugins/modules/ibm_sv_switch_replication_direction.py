#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2022 IBM CORPORATION
# Author(s): Shilpi Jain <shilpi.jain1@ibm.com>
#
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_sv_switch_replication_direction
short_description: This module switches the replication direction on IBM Storage Virtualize family systems
version_added: '1.10.0'
description:
  - Ansible interface to manage the chvolumegroupreplication command.
  - This module can be used to switch replication direction.
options:
    clustername:
        description:
            - The hostname or management IP of the Storage Virtualize system.
        required: true
        type: str
    domain:
        description:
            - Domain for the Storage Virtualize system.
            - Valid when the hostname is used for the parameter I(clustername).
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
    name:
        description:
            - Specifies the name of the volume group.
        type: str
        required: true
    mode:
        description:
            - Specifies the replication mode of the volume group.
        choices: [ independent, production ]
        required: true
        type: str
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
- name: Switch to independent mode
  ibm.storage_virtualize.ibm_sv_switch_replication_direction:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    mode: independent
    name: vg0
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (
    IBMSVCRestApi, svc_argument_spec,
    get_logger
)
from ansible.module_utils._text import to_native


class IBMSVSwitchReplication:

    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                name=dict(
                    type='str',
                    required=True
                ),
                mode=dict(
                    type='str',
                    choices=['independent', 'production'],
                    required=True
                )
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # Required parameters
        self.name = self.module.params['name']
        self.mode = self.module.params['mode']

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
        if not self.name:
            self.module.fail_json(
                msg='Missing mandatory parameter: name'
            )

    # function to check whether volume group exists or not
    def get_volumegroup_info(self):
        return self.restapi.svc_obj_info(
            'lsvolumegroup', None, [self.name]
        )

    def change_vg_mode(self):
        cmd = 'chvolumegroupreplication'
        cmdopts = {}
        cmdopts["mode"] = self.mode
        self.log("Changing replicaiton direction.. Command %s opts %s", cmd, cmdopts)
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=[self.name])

    def apply(self):
        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'
        else:
            if self.get_volumegroup_info():
                self.change_vg_mode()
                self.changed = True
                self.msg = "Replication direction on volume group [%s] has been modified." % self.name
            else:
                self.module.fail_json(msg="Volume group does not exist: [%s]" % self.name)

        self.module.exit_json(
            changed=self.changed,
            msg=self.msg
        )


def main():
    v = IBMSVSwitchReplication()
    try:
        v.apply()
    except Exception as e:
        v.log('Exception in apply(): \n%s', format_exc())
        v.module.fail_json(msg='Module failed. Error [%s].' % to_native(e))


if __name__ == '__main__':
    main()
