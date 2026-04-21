#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2022 IBM CORPORATION
# Author(s): Sanjaikumaar M <sanjaikumaar.m@ibm.com>
#            Sumit Kumar Gupta<sumit.gupta16@ibm.com>
#            Sandip Gulab Rajbanshi <sandip.rajbanshi@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_sv_manage_truststore_for_replication
short_description: This module manages certificate trust stores for replication on
                   IBM Storage Virtualize family systems
version_added: '1.10.0'
description:
  - Ansible interface to manage mktruststore and rmtruststore commands.
  - This module transfers the certificate from a remote system to the local system.
  - This module works on SSH and uses paramiko to establish an SSH connection.
  - Once transfer is done successfully, it also adds the certificate to the trust store of the local system.
  - This module can be used to set up mutual TLS (mTLS) for policy-based replication inter-system communication
    using cluster endpoint certificates (usually system-signed which are exported by the
    M(ibm.storage_virtualize.ibm_sv_manage_ssl_certificate) module).
  - To create a truststore for flashsystem grid, a root CA certificate has to be created and exported first. It can be
    achieved via ibm_svctask_command module via command I(chsystemcert -mksystemsigned) and
    I(chsystemcert -exportrootcacert) currently.
options:
    clustername:
        description:
            - The hostname or management IP of the Storage Virtualize system.
        required: true
        type: str
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
            - Mandatory, when I(usesshkey=no).
        type: str
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
    log_path:
        description:
            - Path of debug log file.
        type: str
    state:
        description:
            - Creates (C(present)) or deletes (C(absent)) a trust store.
        choices: [ present, absent ]
        required: true
        type: str
    name:
        description:
            - Specifies the name of the trust store.
        type: str
        required: true
    syslog:
        description:
            - Specifies the certificates to be bundled and provided to rsyslog client for making TLS connections.
        choices: [ 'on', 'off' ]
        type: str
        version_added: 2.5.0
    restapi:
        description:
            - Specifies the certificates in the store are used for the REST API.
        choices: [ 'on', 'off' ]
        type: str
        version_added: 2.5.0
    ipsec:
        description:
            - Specifies the certificates in the store are used for the IPsec service.
        choices: [ 'on', 'off' ]
        type: str
        version_added: 2.5.0
    vasa:
        description:
            - Specifies the certificates in the store are used for the VASA Provider.
        choices: [ 'on', 'off' ]
        type: str
        version_added: 2.5.0
    email:
        description:
            - Specifies the certificates in the store are used to validate the email server.
        choices: [ 'on', 'off' ]
        type: str
        version_added: 2.5.0
    snmp:
        description:
            - Specifies the certificates in the store are used to validate the SNMP servers.
        choices: [ 'on', 'off' ]
        type: str
        version_added: 2.5.0
    flashgrid:
        description:
            - Specifies the certificates in the store are used for the flashsystem grid.
        choices: [ 'on', 'off' ]
        type: str
        version_added: 2.7.0
    remote_clustername:
        description:
            - Specifies the name of the partner remote cluster with which mTLS partnership needs to be setup.
        type: str
    remote_domain:
        description:
            - Domain for the Storage Virtualize storage system.
            - Valid when hostname is used for the parameter I(remote_clustername).
        type: str
    remote_username:
        description:
            - Username for remote cluster.
            - Applies when I(state=present) to create a trust store.
        type: str
    remote_password:
        description:
            - Password for remote cluster.
            - Applies when I(state=present) to create a trust store.
        type: str
author:
    - Sanjaikumaar M(@sanjaikumaar)
    - Sumit Kumar Gupta (@sumitguptaibm)
    - Sandip Gulab Rajbanshi (@Sandip-Rajbanshi)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create truststore with email settings enabled
  ibm.storage_virtualize.ibm_sv_manage_truststore_for_replication:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    remote_clustername: "{{ remote_clustername }}"
    remote_username: "{{ remote_username }}"
    remote_password: "{{ remote_password }}"
    log_path: "{{ log_path }}"
    email: "on"
    state: "present"
- name: Turn-on syslog facility in existing truststore so that certificates are bundled and provide to rsyslog client
  ibm.storage_virtualize.ibm_sv_manage_truststore_for_replication:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    log_path: "{{ log_path }}"
    syslog: "on"
    state: "present"
- name: Turn-on restapi flag in existing truststore so that certificates in the store are used for the REST API
  ibm.storage_virtualize.ibm_sv_manage_truststore_for_replication:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    log_path: "{{ log_path }}"
    restapi: "on"
    state: "present"
- name: Create truststore for flashsystem grid
  ibm.storage_virtualize.ibm_sv_manage_truststore_for_replication:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    remote_clustername: "{{ remote_clustername }}"
    remote_username: "{{ remote_username }}"
    remote_password: "{{ remote_password }}"
    log_path: "{{ log_path }}"
    flashgrid: "on"
    state: "present"
- name: Delete truststore
  ibm.storage_virtualize.ibm_sv_manage_truststore_for_replication:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    log_path: "{{ log_path }}"
    state: "absent"
'''

RETURN = '''#'''

from traceback import format_exc
import json
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import (
    svc_ssh_argument_spec,
    get_logger
)
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_ssh import IBMSVCssh
from ansible.module_utils._text import to_native


class IBMSVTrustStore:

    def __init__(self):
        argument_spec = svc_ssh_argument_spec()
        argument_spec.update(
            dict(
                password=dict(
                    type='str',
                    required=False,
                    no_log=True
                ),
                name=dict(
                    type='str',
                    required=True
                ),
                syslog=dict(
                    type='str',
                    choices=['on', 'off']
                ),
                restapi=dict(
                    type='str',
                    choices=['on', 'off']
                ),
                ipsec=dict(
                    type='str',
                    choices=['on', 'off']
                ),
                vasa=dict(
                    type='str',
                    choices=['on', 'off']
                ),
                email=dict(
                    type='str',
                    choices=['on', 'off']
                ),
                snmp=dict(
                    type='str',
                    choices=['on', 'off']
                ),
                flashgrid=dict(
                    type='str',
                    choices=['on', 'off']
                ),
                usesshkey=dict(
                    type='str',
                    default='no',
                    choices=['yes', 'no']
                ),
                key_filename=dict(
                    type='str',
                ),
                state=dict(
                    type='str',
                    choices=['present', 'absent'],
                    required=True
                ),
                remote_clustername=dict(
                    type='str'
                ),
                remote_domain=dict(
                    type='str'
                ),
                remote_username=dict(
                    type='str'
                ),
                remote_password=dict(
                    type='str',
                    no_log=True
                ),
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # logging setup
        self.log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, self.log_path)
        self.log = log.info

        # Required parameters
        self.name = self.module.params['name']
        self.state = self.module.params['state']
        self.remote_clustername = self.module.params['remote_clustername']

        # local SSH keys will be used in case of password less SSH connection
        self.usesshkey = self.module.params['usesshkey']
        self.key_filename = self.module.params['key_filename']

        # Optional parameters
        self.domain = self.module.params.get('domain', '')
        self.password = self.module.params.get('password', '')
        self.name = self.module.params.get('name', '')
        self.syslog = self.module.params.get('syslog', '')
        self.restapi = self.module.params.get('restapi', '')
        self.ipsec = self.module.params.get('ipsec', '')
        self.vasa = self.module.params.get('vasa', '')
        self.email = self.module.params.get('email', '')
        self.snmp = self.module.params.get('snmp', '')
        self.flashgrid = self.module.params.get('flashgrid', '')
        self.remote_domain = self.module.params.get('remote_domain', '')
        self.remote_username = self.module.params.get('remote_username', '')
        self.remote_password = self.module.params.get('remote_password', '')

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
                self.module.fail_json(msg="You must pass either password or usesshkey parameter.")
        else:
            self.log("password is given")
            self.look_for_keys = False

        self.basic_checks()

        # Dynamic variables
        self.changed = False
        self.msg = ''

        self.ssh_client = IBMSVCssh(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.domain,
            username=self.module.params['username'],
            password=self.password,
            look_for_keys=self.look_for_keys,
            key_filename=self.key_filename,
            log_path=self.log_path
        )

    def basic_checks(self):
        if self.state == 'absent':
            unsupported = ('remote_clustername', 'remote_username', 'remote_password',
                           'syslog', 'restapi', 'ipsec', 'vasa', 'email', 'snmp', 'flashgrid')
            unsupported_exists = ', '.join((field for field in unsupported if getattr(self, field)))
            if unsupported_exists:
                self.module.fail_json(
                    msg='state=absent but following parameters have been passed: {0}'.format(unsupported_exists)
                )

    def raise_error(self, stderr):
        message = stderr.read().decode('utf-8')
        if len(message) > 0:
            self.log("%s", message)
            self.module.fail_json(msg=message)
        else:
            message = 'Unknown error received.'
            self.module.fail_json(msg=message)

    def is_truststore_present(self):
        merged_result = {}
        cmd = 'lstruststore -json {0}'.format(self.name)
        stdin, stdout, stderr = self.ssh_client.client.exec_command(cmd)
        result = stdout.read().decode('utf-8')

        if result:
            result = json.loads(result)
        else:
            return merged_result

        rc = stdout.channel.recv_exit_status()
        if rc > 0:
            message = stderr.read().decode('utf-8')
            if (message.count('CMMVC5804E') != 1) or (message.count('CMMVC6035E') != 1):
                self.log("Error in executing CLI command: %s", cmd)
                self.log("%s", message)
                self.module.fail_json(msg=message)
            else:
                self.log("Expected error: %s", message)

        if isinstance(result, list):
            for d in result:
                merged_result.update(d)
        else:
            merged_result = result

        return merged_result

    def download_file(self):
        if self.module.check_mode:
            return

        self.remote_hostname = f"{self.remote_clustername}.{self.remote_domain}" if self.remote_domain else self.remote_clustername
        cert_file = "rootcacertificate.pem" if self.flashgrid == "on" else "certificate.pem"

        # Assisted by watsonx Code Assistant
        cmd = 'scp -O -o stricthostkeychecking=no -o UserKnownHostsFile=/dev/null {0}@{1}:/dumps/{2} /upgrade/'.format(
              self.remote_username,
              self.remote_hostname,
              cert_file)

        self.log('Command to be executed: %s', cmd)
        stdin, stdout, stderr = self.ssh_client.client.exec_command(cmd, get_pty=True, timeout=60 * 1.5)
        result = ''
        while not stdout.channel.recv_ready():
            data = stdout.channel.recv(1024)
            self.log(str(data, 'utf-8'))
            if data:
                if b'Warning: Permanently added' in data:
                    while not (b'Password' in data or b'password' in data):
                        data = stdout.channel.recv(1024)
                if b'Password' in data or b'password' in data:
                    stdin.write("{0}\n".format(self.remote_password))
                    stdin.flush()
                else:
                    if isinstance(data, bytes):
                        result += data.decode('utf-8')
                    else:
                        result += data.read().decode('utf-8')
                break
        if isinstance(stdout, bytes):
            # Decode the bytes object directly
            result += stdout.decode('utf-8')
        else:
            result += stdout.read().decode('utf-8')
        rc = stdout.channel.recv_exit_status()
        if rc > 0:
            if isinstance(stderr, bytes):
                message = stderr.decode('utf-8')
            else:
                message = stderr.read().decode('utf-8')
            self.log("Error in executing command: %s", cmd)
            if not len(message) > 1:
                if len(result) > 1:
                    err = result.replace('\rPassword:\r\n', '')
                    self.log("Error: %s", err)
                    if err:
                        self.module.fail_json(msg=err)
                self.module.fail_json(msg='Unknown error received')
            else:
                self.module.fail_json(msg=message)
        else:
            self.log(result)

    def create_validation(self):
        # Test missing parameters for creation of truststore
        mandatory_params = ['remote_clustername', 'remote_username', 'remote_password']
        missing_params = [param for param in mandatory_params if not getattr(self, param)]

        # Fail if there are any missing parameters
        if missing_params:
            self.module.fail_json(
                msg=f"Missing mandatory parameters: {', '.join(missing_params)}"
            )

    def create_truststore(self):
        self.create_validation()
        if self.module.check_mode:
            self.changed = True
            return

        cert_file = "rootcacertificate.pem" if self.flashgrid == "on" else "certificate.pem"

        cmd = 'mktruststore -name {0} -file /upgrade/{1}'.format(self.name, cert_file)
        if self.syslog:
            cmd += ' -syslog {0}'.format(self.syslog)
        if self.restapi:
            cmd += ' -restapi {0}'.format(self.restapi)
        if self.ipsec:
            cmd += ' -ipsec {0}'.format(self.ipsec)
        if self.vasa:
            cmd += ' -vasa {0}'.format(self.vasa)
        if self.email:
            cmd += ' -email {0}'.format(self.email)
        if self.snmp:
            cmd += ' -snmp {0}'.format(self.snmp)
        if self.flashgrid:
            cmd += ' -flashgrid {0}'.format(self.flashgrid)

        self.log('Command to be executed: %s', cmd)
        stdin, stdout, stderr = self.ssh_client.client.exec_command(cmd)
        result = stdout.read().decode('utf-8')
        rc = stdout.channel.recv_exit_status()

        if rc > 0:
            self.log("Error in executing command: %s", cmd)
            self.raise_error(stderr)
        else:
            self.log('Truststore (%s) created', self.name)
            self.log(result)
            self.changed = True

    def probe_truststore(self, data):
        # If truststore exists, change required fields
        modified_props = {}

        for prop in ['syslog', 'restapi', 'ipsec', 'email', 'snmp', 'vasa']:
            value = getattr(self, prop, None)
            if value and value != data.get(prop):
                modified_props[prop] = value
        if data.get("flash_grid_references"):
            if self.flashgrid == "off":
                self.module.fail_json(msg="Invalid parameter for update: (flashgrid)")
        elif self.flashgrid:
            self.module.fail_json(msg="Invalid parameter for update: (flashgrid)")
        return modified_props

    def update_validation(self):
        # Test missing parameters for updating truststore
        if not self.name:
            self.module.fail_json(msg="Missing mandatory parameter: name")
        # Even though probe_truststore() throws error for flashgrid attribute,
        # self.flashgrid has to be checked here for supporting check_mode=True
        if self.flashgrid:
            self.log("Flashgrid parameter cannot be modified.")
            self.module.fail_json(msg="Invalid parameter for update: flashgrid")

    def update_truststore(self, modified_props):
        self.update_validation()
        if self.module.check_mode:
            self.changed = True
            return

        self.log("Modifying truststore properties: ")
        # The reason to probe before running update_truststore, is to avoid running a CLI in case of no change
        cmd = 'chtruststore'
        for prop in modified_props:
            if modified_props[prop]:
                cmd += ' -' + prop + ' ' + str(modified_props[prop])

        cmd += ' {0}'.format(self.name)
        self.log('Command to be executed: %s', cmd)
        stdin, stdout, stderr = self.ssh_client.client.exec_command(cmd)
        result = stdout.read().decode('utf-8')
        rc = stdout.channel.recv_exit_status()

        if rc > 0:
            self.log("Error in executing command: %s", cmd)
            self.raise_error(stderr)
        else:
            self.log('Truststore (%s) updated', self.name)
            self.log(result)
            self.changed = True
        return

    def delete_validation(self):
        # Test missing parameters for updating truststore
        if not self.name:
            self.module.fail_json(msg="Missing mandatory parameter: name")

    def delete_truststore(self):
        self.delete_validation()
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'rmtruststore {0}'.format(self.name)
        self.log('Command to be executed: %s', cmd)
        stdin, stdout, stderr = self.ssh_client.client.exec_command(cmd)
        result = stdout.read().decode('utf-8')
        rc = stdout.channel.recv_exit_status()

        if rc > 0:
            self.log("Error in executing command: %s", cmd)
            self.raise_error(stderr)
        else:
            self.log('Truststore (%s) deleted', self.name)
            self.log(result)
            self.changed = True

    def apply(self):
        truststore_data = self.is_truststore_present()
        if truststore_data:
            self.log("Truststore (%s) exists", self.name)
            if self.state == 'present':
                modified_props = self.probe_truststore(truststore_data)
                if modified_props:
                    self.update_truststore(modified_props)
                    self.msg = 'Truststore ({0}) updated'.format(self.name)
                else:
                    self.msg = 'Truststore ({0}) already exist. No modifications done'.format(self.name)
            else:
                self.delete_truststore()
                self.msg = 'Truststore ({0}) deleted.'.format(self.name)
        else:
            if self.state == 'absent':
                self.msg = 'Truststore ({0}) does not exist. No modifications done.'.format(self.name)
            else:
                self.download_file()
                self.create_truststore()
                self.msg = 'Truststore ({0}) created.'.format(self.name)

        if self.module.check_mode:
            self.msg = 'skipping changes due to check mode.'

        self.module.exit_json(
            changed=self.changed,
            msg=self.msg
        )


def main():
    v = IBMSVTrustStore()
    try:
        v.apply()
    except Exception as e:
        v.log('Exception in apply(): \n%s', format_exc())
        v.module.fail_json(msg='Module failed. Error [%s].' % to_native(e))


if __name__ == '__main__':
    main()
