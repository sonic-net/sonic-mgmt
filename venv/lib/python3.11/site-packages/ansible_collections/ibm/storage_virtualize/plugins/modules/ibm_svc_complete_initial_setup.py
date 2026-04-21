#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2022 IBM CORPORATION
# Author(s): Shilpi Jain <shilpi.jain1@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_complete_initial_setup
short_description: This module completes the initial setup configuration for LMC systems
description:
  - It disables the GUI setup wizard for LMC systems.
  - It is recommended to run this module after using ibm_svc_initial_setup module for intial setup configuration.
  - This module works on SSH. Paramiko must be installed to use this module.
version_added: "1.8.0"
options:
  clustername:
    description:
    - The hostname or management IP of the Storage Virtualize system.
    type: str
    required: true
  domain:
    description:
    - Domain for the Storage Virtualize storage system.
    - Valid when hostname is used for the parameter I(clustername).
    type: str
  username:
    description:
    - Username for the Storage Virtualize system.
    type: str
    required: true
  password:
    description:
    - Password for the Storage Virtualize system.
    type: str
    required: true
  log_path:
    description:
    - Path of debug log file.
    type: str
author:
    - Shilpi Jain(@Shilpi-J)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: complete intial setup
  ibm.storage_virtualize.ibm_svc_complete_initial_setup:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
'''

RETURN = '''# '''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import svc_ssh_argument_spec, get_logger
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_ssh import IBMSVCssh


class IBMSVCCompleteSetup(object):
    def __init__(self):
        argument_spec = svc_ssh_argument_spec()

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        self.domain = self.module.params.get('domain', '')

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        self.ssh_client = IBMSVCssh(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.domain,
            username=self.module.params['username'],
            password=self.module.params['password'],
            look_for_keys=None,
            key_filename=None,
            log_path=log_path
        )

    def is_lmc(self):
        info_output = ""

        cmd = 'svcinfo lsguicapabilities'
        stdin, stdout, stderr = self.ssh_client.client.exec_command(cmd)

        for line in stdout.readlines():
            info_output += line
        if 'login_eula yes' in info_output:
            self.log("The system is non LMC")
            return False
        else:
            self.log("The system is LMC")
            return True

    def disable_setup_wizard(self):
        self.log("Disable setup wizard")

        cmd = 'chsystem -easysetup no'

        stdin, stdout, stderr = self.ssh_client.client.exec_command(cmd)

    def apply(self):
        changed = False
        is_lmc = False
        msg = ""

        if self.module.check_mode:
            msg = "skipping changes due to check mode"
        else:
            if not self.ssh_client.is_client_connected:
                self.module.fail_json(msg="SSH client not connected")

            is_lmc = self.is_lmc()
            if is_lmc:
                self.disable_setup_wizard()
                changed = True
                msg += "Initial Setup configuration completed. Setup wizard is disabled."
                self.ssh_client._svc_disconnect()
                self.module.exit_json(msg=msg, changed=changed)
            else:
                msg += "This is a non LMC system. Please log in GUI to accept EULA. "
                msg += "More details are available in README (https://github.com/ansible-collections/ibm.storage_virtualize)."
                self.ssh_client._svc_disconnect()
                self.module.fail_json(msg=msg, changed=changed)


def main():
    v = IBMSVCCompleteSetup()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
