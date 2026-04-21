# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""
ntc_templates parser

This is the ntc_templates parser for use with the cli_parse module and action plugin.
https://github.com/networktocode/ntc-templates

"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    author: Bradley Thornton (@cidrblock)
    name: ntc_templates
    short_description: Define configurable options for C(ntc_templates) sub-plugin of C(cli_parse) module
    description:
    - This plugin documentation provides the configurable options that can be passed
      to the I(ansible.utils.cli_parse) plugins when I(ansible.netcommon.ntc_templates) is used as a value for
      I(name) option.
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: "Run command and parse with ntc_templates"
  ansible.utils.cli_parse:
    command: "show interface"
    parser:
      name: ansible.netcommon.ntc_templates
  register: nxos_ntc_templates_command

- name: "Pass text and command"
  ansible.utils.cli_parse:
    text: "{{ nxos_ntc_templates_command['stdout'] }}"
    parser:
      name: ansible.netcommon.ntc_templates
      command: show interface
  register: nxos_ntc_templates_text
"""

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.ansible.utils.plugins.plugin_utils.base.cli_parser import CliParserBase


try:
    from ntc_templates.parse import parse_output

    HAS_NTC = True
except ImportError:
    HAS_NTC = False

ANSIBLE_NETWORK_OS = {
    "ios": "cisco_ios",
    "iosxr": "cisco_xr",
    "nxos": "cisco_nxos",
    "asa": "cisco_asa",
    "eos": "arista_eos",
    "junos": "juniper_junos",
}


class CliParser(CliParserBase):
    """The ntc_templates parser class
    Convert raw text to structured data using textfsm and predefined templates in
    the ntc-templates python package
    """

    DEFAULT_TEMPLATE_EXTENSION = None
    PROVIDE_TEMPLATE_CONTENTS = False

    def _check_reqs(self):
        """Check the prerequisites for the ntc template parser

        :return: A dict with errors or a network_os and command
        :rtype: dict
        """
        errors = []

        if not HAS_NTC:
            errors.append(missing_required_lib("ntc-templates"))

        network_os = self._task_args.get("parser").get("os")
        if network_os:
            self._debug("OS set to {os} using task args".format(os=network_os))
        if not network_os:
            ano = self._task_vars.get("ansible_network_os", "").split(".")[-1]
            network_os = ANSIBLE_NETWORK_OS[ano]
            self._debug("OS set to {os} using ansible_network_os".format(os=network_os))
        if not network_os:
            errors.append("Either 'parser/os' needs to be specified or 'ansible_network_os' set.")
        command = self._task_args.get("parser").get("command")
        if not command:
            errors.append("'command' needs to be specified.")

        if errors:
            return {"errors": errors}
        return {"network_os": network_os, "command": command}

    def parse(self, *_args, **_kwargs):
        """Std entry point for a cli_parse parse execution

        :return: Errors or parsed text as structured data
        :rtype: dict

        :example:

        The parse function of a parser should return a dict:
        {"errors": [a list of errors]}
        or
        {"parsed": obj}
        """
        cli_output = self._task_args.get("text")
        res = self._check_reqs()
        if res.get("errors"):
            return {"errors": res.get("errors")}
        platform = res["network_os"]
        command = res["command"]
        try:
            parsed = parse_output(platform=platform, command=command, data=cli_output)
            return {"parsed": parsed}
        except Exception as exc:
            return {"errors": [to_native(exc)]}
