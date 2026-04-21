# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""
native parser

This is the native parser for use with the cli_parse module and action plugin.
The parser functionality used by the network resource modules is leveraged here.

"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    author: Bradley Thornton (@cidrblock)
    name: native
    short_description: Define configurable options for C(native) sub-plugin of C(cli_parse) module
    description:
    - This plugin documentation provides the configurable options that can be passed
      to the I(ansible.utils.cli_parse) plugins when I(ansible.netcommon.native) is used as a value for
      I(name) option.
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: "Run command and parse with native"
  ansible.utils.cli_parse:
    command: "show interface"
    parser:
      name: ansible.netcommon.native
    set_fact: POpqMQoJWTiDpEW
  register: nxos_native_command

- name: "Pass text and template_path"
  ansible.utils.cli_parse:
    text: "{{ nxos_native_command['stdout'] }}"
    parser:
      name: ansible.netcommon.native
      template_path: "/home/user/templates/nxos_show_interface.yaml"
  register: nxos_native_text
"""

from ansible.module_utils.common.text.converters import to_native
from ansible_collections.ansible.utils.plugins.plugin_utils.base.cli_parser import CliParserBase

from ansible_collections.ansible.netcommon.plugins.module_utils.cli_parser.cli_parsertemplate import (
    CliParserTemplate,
)


try:
    import yaml

    try:
        from yaml import CSafeLoader as SafeLoader
    except ImportError:
        from yaml import SafeLoader
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class CliParser(CliParserBase):
    """The native parser class
    Convert raw text to structured data using the resource module parser
    """

    DEFAULT_TEMPLATE_EXTENSION = "yaml"
    PROVIDE_TEMPLATE_CONTENTS = True

    def parse(self, *_args, **kwargs):
        """Std entry point for a cli_parse parse execution

        :return: Errors or parsed text as structured data
        :rtype: dict

        :example:

        The parse function of a parser should return a dict:
        {"errors": [a list of errors]}
        or
        {"parsed": obj}
        """
        # res = self._check_reqs()
        # if res.get("errors"):
        #     return res

        template_contents = kwargs["template_contents"]
        parser = CliParserTemplate(lines=self._task_args.get("text", "").splitlines())
        try:
            template_obj = yaml.load(template_contents, SafeLoader)
        except Exception as exc:
            return {"errors": [to_native(exc)]}

        try:
            parser.PARSERS = template_obj
            return {"parsed": parser.parse()}
        except Exception as exc:
            msg = "Native parser returned an error while parsing. Error: {err}"
            return {"errors": [msg.format(err=to_native(exc))]}
