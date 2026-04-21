# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""
pyats parser

This is the pyats parser for use with the cli_parse module and action plugin.
https://developer.cisco.com/docs/pyats/#!parsing-device-output

"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    author: Bradley Thornton (@cidrblock)
    name: pyats
    short_description: Define configurable options for C(pyats) sub-plugin of C(cli_parse) module
    description:
    - This plugin documentation provides the configurable options that can be passed
      to the I(ansible.utils.cli_parse) plugins when I(ansible.netcommon.pyats) is used as a value for
      I(name) option.
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: "Run command and parse with pyats"
  ansible.utils.cli_parse:
    command: "show interface"
    parser:
      name: ansible.netcommon.pyats
  register: nxos_pyats_command

- name: "Pass text and command"
  ansible.utils.cli_parse:
    text: "{{ nxos_pyats_command['stdout'] }}"
    parser:
      name: ansible.netcommon.pyats
      command: show interface
  register: nxos_pyats_text
"""

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.ansible.utils.plugins.plugin_utils.base.cli_parser import CliParserBase


try:
    from genie.conf.base import Device

    HAS_GENIE = True
except ImportError:
    HAS_GENIE = False

try:
    from pyats.datastructures import AttrDict

    HAS_PYATS = True
except ImportError:
    HAS_PYATS = False


class CliParser(CliParserBase):
    """The pyats parser class
    Convert raw text to structured data using pyats/genie
    """

    DEFAULT_TEMPLATE_EXTENSION = None
    PROVIDE_TEMPLATE_CONTENTS = False

    @staticmethod
    def _check_reqs():
        """Check the prerequisites are installed for pyats/genie

        :return dict: A dict with a list of errors
        """
        errors = []
        if not HAS_GENIE:
            errors.append(missing_required_lib("genie"))
        if not HAS_PYATS:
            errors.append(missing_required_lib("pyats"))
        return errors

    def _check_vars(self):
        """Ensure specific args are set

        :return: A dict with a list of errors
        :rtype: dict
        """
        errors = []
        if not self._task_args.get("parser").get("command"):
            errors.append("The pyats parser requires parser/command be provided.")
        return errors

    def _transform_ansible_network_os(self):
        """Transform the ansible_network_os to a pyats OS
        The last part of the fully qualified name is used
        org.name.platform => platform

        In the case of ios, the os is assumed to be iosxe
        """
        ane = self._task_vars.get("ansible_network_os", "").split(".")[-1]
        if ane == "ios":
            self._debug("ansible_network_os was ios, using iosxe.")
            ane = "iosxe"
        self._debug("OS set to '{ane}' using 'ansible_network_os'.".format(ane=ane))
        return ane

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
        errors = self._check_reqs()
        errors.extend(self._check_vars())
        if errors:
            return {"errors": errors}

        command = self._task_args.get("parser").get("command")
        network_os = self._task_args.get("parser").get("os") or self._transform_ansible_network_os()
        cli_output = self._task_args.get("text")

        device = Device("new_device", os=network_os)
        device.custom.setdefault("abstraction", {})["order"] = ["os"]
        device.cli = AttrDict({"execute": None})

        try:
            parsed = device.parse(command, output=cli_output)
        except Exception as exc:
            msg = "The pyats library return an error for '{cmd}' for '{os}'. Error: {err}."
            return {"errors": [msg.format(cmd=command, os=network_os, err=to_native(exc))]}
        return {"parsed": parsed}
