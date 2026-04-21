#!/usr/bin/python
'''
# (c) 2020-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Run cli commands on ONTAP over SSH using paramiko.
  - Output is returned in C(stdout) and C(stderr), and also as C(stdout_lines), C(stdout_lines_filtered), C(stderr_lines).
  - Note that the module can succeed even though the command failed.  You need to analyze stdout and check the results.
  - If the SSH host key is unknown and accepted, C(warnings) is updated.
  - Options related to ZAPI or REST APIs are ignored.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
module: na_ontap_ssh_command
short_description: NetApp ONTAP Run any cli command over plain SSH using paramiko.
version_added: 20.8.0
options:
    command:
        description:
          - a string containing the command and arguments.
        required: true
        type: str
    privilege:
        description:
          - privilege level at which to run the command, eg admin, advanced.
          - if set, the command is prefixed with C(set -privilege <privilege>;).
        type: str
    accept_unknown_host_keys:
        description:
          - When false, reject the connection if the host key is not in known_hosts file.
          - When true, if the host key is unknown, accept it, but report a warning.
          - Note that the key is not added to the file.  You could add the key by manually using SSH.
        type: bool
        default: false
    include_lines:
        description:
          - return only lines containing string pattern in C(stdout_lines_filtered)
        default: ''
        type: str
    exclude_lines:
        description:
          - return only lines containing string pattern in C(stdout_lines_filtered)
        default: ''
        type: str
    service_processor:
        description:
        - whether the target system is ONTAP or the service processor (SP)
        - only menaningful when privilege is set
        aliases: [sp]
        default: false
        type: bool
'''

EXAMPLES = """
- name: run ontap cli command using SSH
  netapp.ontap.na_ontap_ssh_command:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    command: version

# Same as above, with parameters
- name: run ontap cli command
  netapp.ontap.na_ontap_ssh_command:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    command: node show -fields node,health,uptime,model
    privilege: admin

# Same as above, but with lines filtering
- name: run ontap cli command
  netapp.ontap.na_ontap_ssh_command:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    command: node show -fields node,health,uptime,model
    exclude_lines: 'ode ' # Exclude lines with 'Node ' or 'node'
    # use with caution!
    accept_unknown_host_keys: true
    privilege: admin

- name: run ontap SSH command on SP
  netapp.ontap.na_ontap_ssh_command:
    # <<: *sp_login
    command: sp switch-version
    privilege: diag
    sp: true
    register: result
"""

RETURN = """
stdout_lines_filtered:
  description:
    - In addition to stdout and stdout_lines, a list of non-white lines, excluding last and failed login information.
    - The list can be further refined using the include_lines and exclude_lines filters.
  returned: always
  type: list
"""

import traceback
import warnings
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


class NetAppONTAPSSHCommand(object):
    ''' calls a CLI command using SSH'''

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            command=dict(required=True, type='str'),
            privilege=dict(required=False, type='str'),
            accept_unknown_host_keys=dict(required=False, type='bool', default=False),
            include_lines=dict(required=False, type='str', default=''),
            exclude_lines=dict(required=False, type='str', default=''),
            service_processor=dict(required=False, type='bool', default=False, aliases=['sp']),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        parameters = self.module.params
        # set up state variables
        self.command = parameters['command']
        self.privilege = parameters['privilege']
        self.include_lines = parameters['include_lines']
        self.exclude_lines = parameters['exclude_lines']
        self.accept_unknown_host_keys = parameters['accept_unknown_host_keys']
        self.service_processor = parameters['service_processor']
        self.warnings = list()
        self.failed = False

        if not HAS_PARAMIKO:
            self.module.fail_json(msg="the python paramiko module is required")

        client = paramiko.SSHClient()
        client.load_system_host_keys()      # load ~/.ssh/known_hosts if it exists
        if self.accept_unknown_host_keys:
            # accept unknown key, but raise a python warning
            client.set_missing_host_key_policy(paramiko.WarningPolicy())

        with warnings.catch_warnings(record=True) as wngs:
            try:
                client.connect(hostname=parameters['hostname'], username=parameters['username'], password=parameters['password'])
                if len(wngs) > 0:
                    self.warnings.extend([str(warning.message) for warning in wngs])
            except paramiko.SSHException as exc:
                self.module.fail_json(msg="SSH connection failed: %s" % repr(exc))

        self.client = client

    def parse_output(self, out):
        out_string = out.read()
        # ONTAP makes copious use of \r
        out_string = out_string.replace(b'\r\r\n', b'\n')
        out_string = out_string.replace(b'\r\n', b'\n')
        return out_string

    def run_ssh_command(self, command):
        ''' calls SSH '''
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
        except paramiko.SSHException as exc:
            self.module.fail_json(msg='Error running command %s: %s' %
                                  (command, to_native(exc)),
                                  exception=traceback.format_exc())
        stdin.close()       # if we don't close, we may see a TypeError
        return stdout, stderr

    def filter_output(self, output):
        ''' Generate stdout_lines_filtered list
            Remove login information if found in the first non white lines
        '''
        result = list()
        find_banner = True
        for line in output.splitlines():
            try:
                stripped_line = line.strip().decode()
            except Exception as exc:
                self.warnings.append("Unable to decode ONTAP output.  Skipping filtering.  Error: %s" % repr(exc))
                result.append('ERROR: truncated, cannot decode: %s' % line)
                self.failed = False
                return result

            if not stripped_line:
                continue
            if find_banner and stripped_line.startswith(('Last login time:', 'Unsuccessful login attempts since last login:')):
                continue
            find_banner = False
            if self.exclude_lines:
                if self.include_lines in stripped_line and self.exclude_lines not in stripped_line:
                    result.append(stripped_line)
            elif self.include_lines:
                if self.include_lines in stripped_line:
                    result.append(stripped_line)
            else:
                result.append(stripped_line)

        return result

    def run_command(self):
        ''' calls SSH '''
        command = self.command
        if self.privilege is not None:
            if self.service_processor:
                command = "priv set %s;%s" % (self.privilege, command)
            else:
                command = "set -privilege %s;%s" % (self.privilege, command)
        stdout, stderr = self.run_ssh_command(command)
        stdout_string = self.parse_output(stdout)
        stdout_filtered = self.filter_output(stdout_string)
        return stdout_string, stdout_filtered, self.parse_output(stderr)

    def apply(self):
        ''' calls the command and returns raw output '''
        changed = True
        stdout, filtered, stderr = '', '', ''
        if not self.module.check_mode:
            stdout, filtered, stderr = self.run_command()
            if stderr:
                self.failed = True
        self.module.exit_json(changed=changed, failed=self.failed, stdout=stdout, stdout_lines_filtered=filtered, stderr=stderr, warnings=self.warnings)


def main():
    """
    Execute action from playbook
    """
    command = NetAppONTAPSSHCommand()
    command.apply()


if __name__ == '__main__':
    main()
