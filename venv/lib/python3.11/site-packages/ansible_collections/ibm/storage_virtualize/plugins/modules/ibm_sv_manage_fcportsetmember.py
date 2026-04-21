#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2023 IBM CORPORATION
# Author(s): Sudheesh Reddy Satti<Sudheesh.Reddy.Satti@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_sv_manage_fcportsetmember
short_description: This module manages addition or removal of ports to or from the Fibre Channel(FC) portsets on IBM Storage Virtualize family systems.
version_added: "1.12.0"
description:
  - Ansible interface to manage 'addfcportsetmember' and 'rmfcportsetmember' commands.
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
            - Add (C(present)) or Remove (C(absent)) the FC port ID to or from the FC portset
        choices: [ present, absent ]
        required: true
        type: str
    name:
        description:
            - Specifies the name of the FC portset.
        type: str
        required: true
    fcportid:
        description:
            - Specifies the Fibre Channel I/O port ID of the port.
            - The value can be a decimal number 1 to the maximum number of FC I/O ports.
        type: str
        required: true
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
author:
    - Sudheesh S (@sudheesh-reddy)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Add port ID to the portset
  ibm.storage_virtualize.ibm_sv_manage_fcportsetmember:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   name: portset1
   fcportid: 3
   state: present
- name: Remove port ID from portset
  ibm.storage_virtualize.ibm_sv_manage_fcportsetmember:
   clustername: "{{ cluster }}"
   username: "{{ username }}"
   password: "{{ password }}"
   name: portset1
   fcportid: 3
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


class IBMSVFCPortsetmember:

    def __init__(self):
        argument_spec = svc_argument_spec()
        argument_spec.update(
            dict(
                state=dict(
                    type='str',
                    required=True,
                    choices=['present', 'absent']
                ),
                name=dict(
                    type='str',
                    required=True,
                ),
                fcportid=dict(
                    type='str',
                    required=True,
                )
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # Required parameters
        self.name = self.module.params['name']
        self.state = self.module.params['state']
        self.fcportid = self.module.params['fcportid']

        self.basic_checks()

        # Varialbe to cache data
        self.fcportsetmember_details = None

        # logging setup
        self.log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, self.log_path)
        self.log = log.info
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
            self.module.fail_json(msg='Missing mandatory parameter: name')

        if not self.fcportid:
            self.module.fail_json(msg='Missing mandatory parameter: fcportid ')

    def is_fcportsetmember_exists(self):
        merged_result = {}
        cmd = 'lsfcportsetmember'
        cmdopts = {
            "filtervalue": "portset_name={0}:fc_io_port_id={1}".format(self.name, self.fcportid)
        }
        data = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)

        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        self.fcportsetmember_details = merged_result

        return merged_result

    def add_fcportsetmember(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'addfcportsetmember'
        cmdopts = {
            'portset': self.name,
            'fcioportid': self.fcportid
        }

        self.changed = True
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log('FCPortsetmember (%s) mapping is created with fcportid (%s) successfully.', self.name, self.fcportid)

    def remove_fcportsetmember(self):
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'rmfcportsetmember'
        cmdopts = {
            'portset': self.name,
            'fcioportid': self.fcportid
        }

        self.changed = True
        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log('FCPortsetmember (%s) mapping is removed from fcportid (%s) successfully.', self.name, self.fcportid)

    def apply(self):

        fcportsetmember_data = self.is_fcportsetmember_exists()

        if fcportsetmember_data:
            if self.state == 'present':
                self.msg = 'FCPortsetmember ({0}) mapping with fcportid ({1}) is already exist.'.format(self.name, self.fcportid)
            else:
                self.remove_fcportsetmember()
                self.msg = 'FCPortsetmember ({0}) mapping is removed from fcportid ({1}) successfully.'.format(self.name, self.fcportid)
        else:
            if self.state == 'absent':
                self.msg = 'FCPortsetmember ({0}) mapping does not exist with fcportid ({1}). No modifications done.'.format(self.name, self.fcportid)
            else:
                self.add_fcportsetmember()
                self.msg = 'FCPortsetmember ({0}) mapping is created with fcportid ({1}) successfully.'.format(self.name, self.fcportid)

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'

        self.module.exit_json(
            changed=self.changed,
            msg=self.msg
        )


def main():
    v = IBMSVFCPortsetmember()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
