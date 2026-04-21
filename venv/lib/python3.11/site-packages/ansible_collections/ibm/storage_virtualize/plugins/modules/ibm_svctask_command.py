#!/usr/bin/python
# Copyright (C) 2020 IBM CORPORATION
# Author(s): Shilpi Jain <shilpi.jain1@ibm.com>
#            Rahul Pawar <rahul.p@ibm.com>
#            Sumit Kumar Gupta <sumit.gupta16@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svctask_command
short_description: This module implements SSH Client which helps to run
                   svctask CLI command(s) on IBM Storage Virtualize family systems
version_added: "1.2.0"
description:
- Runs svctask and satask CLI command(s) on IBM Storage Virtualize Family systems.
  In case any command fails while running this module, then the
  module stops processing further commands in the list.
  Paramiko must be installed to use this module.
author:
    - Shilpi Jain (@Shilpi-Jain1)
    - Sumit Kumar Gupta (@sumitguptaibm)
    - Rahul Pawar (@rahulpawaribm)

options:
  command:
    description:
    - A list containing svctask CLI commands to be executed on storage.
    type: list
    elements: str
  usesshkey:
    description:
    - For key-pair based SSH connection, set this field as "yes".
      Provide full path of key in key_filename field.
      If not provided, default path of SSH key is used.
    type: str
    choices: [ 'yes', 'no']
    default: 'no'
  key_filename:
    description:
    - SSH client private key filename. By default, ~/.ssh/id_rsa is used.
    type: str
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
    required: true
    type: str
  password:
    description:
    - Password for the Storage Virtualize system.
    type: str
  log_path:
    description:
    - Path of debug log file.
    type: str
'''

EXAMPLES = '''
- name: Run svctask CLI commands using SSH client with password
  ibm.storage_virtualize.ibm_svctask_command:
    command: [
      "svctask mkvdisk -name {{ volname }} -mdiskgrp '{{ pool }}' -easytier '{{ easy_tier }}' -size {{ size }} -unit {{ unit }}",
      "svctask rmvdisk {{ volname }}"
    ]
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
- name: Run svctask CLI command using passwordless SSH Client
  ibm.storage_virtualize.ibm_svctask_command:
    command: [
      "svctask mkvdisk -name vol0 -mdiskgrp pool0 -easytier off -size 1 -unit gb",
      "svctask rmvdisk vol0"
    ]
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    usesshkey: 'yes'
    log_path: /tmp/ansible.log
- name: Run satask CLI command
  ibm.storage_virtualize.ibm_svctask_command:
    command: "satask snap"
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
- name: Generate and export system-signed root CA certificate
  ibm.storage_virtualize.ibm_svctask_command:
    command: [
      "svctask chsystemcert -mksystemsigned",
      "svctask chsystemcert -exportrootcacert"
    ]
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import svc_ssh_argument_spec, get_logger
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_ssh import IBMSVCssh
from ansible.module_utils._text import to_native


class IBMSVCsshClient(object):
    def __init__(
            self,
            timeout=30,
            cmd_timeout=30.0):
        """
        Constructor for SSH client class.
        """

        argument_spec = svc_ssh_argument_spec()

        argument_spec.update(
            dict(
                password=dict(type='str', required=False, no_log=True),
                command=dict(type='list', elements='str', required=False),
                usesshkey=dict(type='str', required=False, default='no', choices=['yes', 'no']),
                key_filename=dict(type='str', required=False)
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required fields for module
        self.command = self.module.params['command']

        # local SSH keys will be used in case of password less SSH connection
        self.usesshkey = self.module.params['usesshkey']
        self.key_filename = self.module.params['key_filename']

        # Required
        self.clustername = self.module.params['clustername']
        self.username = self.module.params['username']
        self.log_path = log_path

        # Optional
        self.domain = self.module.params.get('domain', '')
        self.password = self.module.params.get('password', '')

        # Handling missing mandatory parameter
        if not self.command:
            self.module.fail_json(msg='Missing mandatory parameter: command')

        if not self.password:
            if self.usesshkey == 'yes':
                self.log("password is none and use ssh private key. Check for its path")
                if self.key_filename:
                    self.log("key file_name is provided, use it")
                    self.look_for_keys = True
                else:
                    self.log("key file_name is not provided, use default one, ~/.ssh/id_rsa.pub")
                    self.look_for_keys = True
            else:
                self.log("password is none and SSH key is not provided")
                self.module.fail_json(msg="You must pass in either password or key for ssh")
        else:
            self.log("password is given")
            self.look_for_keys = False

        self.ssh_client = IBMSVCssh(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.domain,
            username=self.module.params['username'],
            password=self.module.params['password'],
            look_for_keys=self.look_for_keys,
            key_filename=self.key_filename,
            log_path=log_path
        )

    def send_svctask_command(self):
        message = ""
        if self.ssh_client.is_client_connected:
            for cmd in self.command:
                self.log("Executing CLI command: %s", cmd)
                stdin, stdout, stderr = self.ssh_client.client.exec_command(cmd)
                for line in stdout.readlines():
                    message += line
                    self.log(line)
                rc = stdout.channel.recv_exit_status()
                if rc > 0:
                    result = stderr.read()
                    if len(result) > 0:
                        result = result.decode('utf-8')
                        self.log("Error in executing CLI command: %s", cmd)
                        self.log("%s", result)
                        message += result
                    else:
                        message = "Unknown error"
                    self.ssh_client._svc_disconnect()
                    self.module.fail_json(msg=message, rc=rc)
        else:
            message = "SSH client is not connected"
        self.ssh_client._svc_disconnect()
        self.module.exit_json(msg=message, rc=rc, changed=True)


def main():
    v = IBMSVCsshClient()
    try:
        if not v.ssh_client.is_client_connected:
            v.log("SSH Connection failed, retry")
            v.module.exit_json(msg="SSH Connection failed, retry", changed=False)
        else:
            v.send_svctask_command()
    except Exception as e:
        v.ssh_client._svc_disconnect()
        v.log("Exception in running command(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
