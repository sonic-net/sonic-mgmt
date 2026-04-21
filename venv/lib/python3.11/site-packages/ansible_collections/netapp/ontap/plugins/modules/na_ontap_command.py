#!/usr/bin/python
'''
# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Run system-cli commands on ONTAP.
  - Can't be used with cert authentication and domain authentication accounts.
  - Requires ontapi and console permissions. Console is not supported for data vservers.
  - Requires write permissions, even for show commands!  ONTAP reports
    "Insufficient privileges" and "user 'xxxxx' does not have write access to this resource"
    for a readonly user.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap_zapi
module: na_ontap_command
short_description: NetApp ONTAP Run any cli command, the username provided needs to have console login permission.
version_added: 2.7.0
options:
    command:
        description:
        - a comma separated list containing the command and arguments.
        required: true
        type: list
        elements: str
    privilege:
        description:
        - privilege level at which to run the command.
        choices: ['admin', 'advanced']
        default: admin
        type: str
        version_added: 2.8.0
    return_dict:
        description:
        - Returns a parsesable dictionary instead of raw XML output
        - C(result_value)
        - C(status) > passed, failed.
        - C(stdout) > command output in plaintext.
        - C(stdout_lines) > list of command output lines.
        - C(stdout_lines_filter) > empty list or list of command output lines matching I(include_lines) or I(exclude_lines) parameters.
        - C(xml_dict) > JSON representation of what the CLI returned.
        type: bool
        default: false
        version_added: 2.9.0
    vserver:
        description:
        - If running as vserver admin, you must give a I(vserver) or module will fail
        version_added: "19.10.0"
        type: str
    include_lines:
        description:
        - applied only when I(return_dict) is true
        - return only lines containing string pattern in C(stdout_lines_filter)
        default: ''
        type: str
        version_added: "19.10.0"
    exclude_lines:
        description:
        - applied only when I(return_dict) is true
        - return only lines containing string pattern in C(stdout_lines_filter)
        default: ''
        type: str
        version_added: "19.10.0"
'''

EXAMPLES = """
- name: Run ONTAP CLI command
  netapp.ontap.na_ontap_command:
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    command: ['version']

# Same as above, but returns parseable dictonary
- name: Run ONTAP CLI command
  netapp.ontap.na_ontap_command:
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    command: ['node', 'show', '-fields', 'node,health,uptime,model']
    privilege: 'admin'
    return_dict: true

# Same as above, but with lines filtering
- name: Run ONTAP CLI command
  netapp.ontap.na_ontap_command:
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    command: ['node', 'show', '-fields', 'node,health,uptime,model']
    exclude_lines: 'ode ' # Exclude lines with 'Node ' or 'node ', or anything else containing 'ode '.
    privilege: 'admin'
    return_dict: true
"""

RETURN = """
"""

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils


class NetAppONTAPCommand():
    ''' calls a CLI command '''

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_zapi_only_spec()
        self.argument_spec.update(dict(
            command=dict(required=True, type='list', elements='str'),
            privilege=dict(required=False, type='str', choices=['admin', 'advanced'], default='admin'),
            return_dict=dict(required=False, type='bool', default=False),
            vserver=dict(required=False, type='str'),
            include_lines=dict(required=False, type='str', default=''),
            exclude_lines=dict(required=False, type='str', default=''),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        parameters = self.module.params
        # set up state variables
        self.command = parameters['command']
        self.privilege = parameters['privilege']
        self.vserver = parameters['vserver']
        self.return_dict = parameters['return_dict']
        self.include_lines = parameters['include_lines']
        self.exclude_lines = parameters['exclude_lines']

        self.result_dict = {
            'status': "",
            'result_value': 0,
            'invoked_command': " ".join(self.command),
            'stdout': "",
            'stdout_lines': [],
            'stdout_lines_filter': [],
            'xml_dict': {},
        }
        self.module.warn('The module only supports ZAPI; refer to netapp.ontap.na_ontap_rest_cli module for RESTful equivalent.')

        if not netapp_utils.has_netapp_lib():
            self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
        self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, wrap_zapi=True)

    def run_command(self):
        ''' calls the ZAPI '''
        command_obj = netapp_utils.zapi.NaElement("system-cli")

        args_obj = netapp_utils.zapi.NaElement("args")
        if self.return_dict:
            args_obj.add_new_child('arg', 'set')
            args_obj.add_new_child('arg', '-showseparator')
            args_obj.add_new_child('arg', '"###"')
            args_obj.add_new_child('arg', ';')
        for arg in self.command:
            args_obj.add_new_child('arg', arg)
        command_obj.add_child_elem(args_obj)
        command_obj.add_new_child('priv', self.privilege)

        try:
            output = self.server.invoke_successfully(command_obj, True)
            if self.return_dict:
                # Parseable dict output
                return self.parse_xml_to_dict(output.to_string())
            else:
                # Raw XML output
                return output.to_string()

        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error running command %s: %s' %
                                  (self.command, to_native(error)),
                                  exception=traceback.format_exc())

    def apply(self):
        ''' calls the command and returns raw output '''
        changed = True
        if self.module.check_mode:
            output = "Would run command: '%s'" % str(self.command)
        else:
            output = self.run_command()
        self.module.exit_json(changed=changed, msg=output)

    def parse_xml_to_dict(self, xmldata):
        '''Parse raw XML from system-cli and create an Ansible parseable dictonary'''
        xml_import_ok = True
        xml_parse_ok = True
        importing = 'ast'

        try:
            import ast
            importing = 'xml.parsers.expat'
            import xml.parsers.expat
        except ImportError:
            self.result_dict['status'] = "XML parsing failed. Cannot import %s!" % importing
            self.result_dict['stdout'] = str(xmldata)
            self.result_dict['result_value'] = -1
            xml_import_ok = False

        if xml_import_ok:
            xml_str = xmldata.decode('utf-8').replace('\n', '---')
            xml_parser = xml.parsers.expat.ParserCreate()
            xml_parser.StartElementHandler = self._start_element
            xml_parser.CharacterDataHandler = self._char_data
            xml_parser.EndElementHandler = self._end_element

            try:
                xml_parser.Parse(xml_str)
            except xml.parsers.expat.ExpatError as errcode:
                self.result_dict['status'] = "XML parsing failed: " + str(errcode)
                self.result_dict['stdout'] = str(xmldata)
                self.result_dict['result_value'] = -1
                xml_parse_ok = False

            if xml_parse_ok:
                self.result_dict['status'] = self.result_dict['xml_dict']['results']['attrs']['status']
                stdout_string = self._format_escaped_data(self.result_dict['xml_dict']['cli-output']['data'])
                self.result_dict['stdout'] = stdout_string
                # Generate stdout_lines list
                for line in stdout_string.split('\n'):
                    stripped_line = line.strip()
                    if len(stripped_line) > 1:
                        self.result_dict['stdout_lines'].append(stripped_line)

                        # Generate stdout_lines_filter_list
                        if self.exclude_lines:
                            if self.include_lines in stripped_line and self.exclude_lines not in stripped_line:
                                self.result_dict['stdout_lines_filter'].append(stripped_line)
                        elif self.include_lines and self.include_lines in stripped_line:
                            self.result_dict['stdout_lines_filter'].append(stripped_line)

                self.result_dict['xml_dict']['cli-output']['data'] = stdout_string
                cli_result_value = self.result_dict['xml_dict']['cli-result-value']['data']
                try:
                    # get rid of extra quotes "'1'", but maybe "u'1'" or "b'1'"
                    cli_result_value = ast.literal_eval(cli_result_value)
                except (SyntaxError, ValueError):
                    pass
                try:
                    self.result_dict['result_value'] = int(cli_result_value)
                except ValueError:
                    self.result_dict['result_value'] = cli_result_value

        return self.result_dict

    def _start_element(self, name, attrs):
        ''' Start XML element '''
        self.result_dict['xml_dict'][name] = {}
        self.result_dict['xml_dict'][name]['attrs'] = attrs
        self.result_dict['xml_dict'][name]['data'] = ""
        self.result_dict['xml_dict']['active_element'] = name
        self.result_dict['xml_dict']['last_element'] = ""

    def _char_data(self, data):
        ''' Dump XML elemet data '''
        self.result_dict['xml_dict'][str(self.result_dict['xml_dict']['active_element'])]['data'] = repr(data)

    def _end_element(self, name):
        self.result_dict['xml_dict']['last_element'] = name
        self.result_dict['xml_dict']['active_element'] = ""

    @classmethod
    def _format_escaped_data(cls, datastring):
        ''' replace helper escape sequences '''
        formatted_string = datastring.replace('------', '---').replace('---', '\n').replace("###", "    ").strip()
        retval_string = ""
        for line in formatted_string.split('\n'):
            stripped_line = line.strip()
            if len(stripped_line) > 1:
                retval_string += stripped_line + "\n"
        return retval_string


def main():
    """
    Execute action from playbook
    """
    command = NetAppONTAPCommand()
    command.apply()


if __name__ == '__main__':
    main()
