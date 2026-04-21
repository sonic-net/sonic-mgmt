"""
ttp parser

This is the ttp parser for use with the cli_parse module and action plugin
https://github.com/dmulyalin/ttp
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    author: Bradley Thornton (@cidrblock)
    name: ttp
    short_description: Define configurable options for C(ttp) sub-plugin of M(ansible.utils.cli_parse) module
    description:
    - This plugin documentation provides the configurable options that can be passed
      to the M(ansible.utils.cli_parse) plugins when I(ansible.utils.ttp) is used as a value for
      I(name) option.
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: "Run command and parse with textfsm"
  ansible.utils.cli_parse:
    command: "show version"
    parser:
      name: ansible.utils.ttp
  register: nxos_ttp_command

- name: "Pass text and command"
  ansible.utils.cli_parse:
    text: "{{ lookup('ansible.builtin.file', '/home/user/files/nxos_show_version.txt') }}"
    parser:
      name: ansible.utils.textfsm
      template_path: "/home/user/templates/nxos_show_version.ttp"
  register: nxos_ttp_text
"""

import os

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import missing_required_lib

from ansible_collections.ansible.utils.plugins.plugin_utils.base.cli_parser import CliParserBase


try:
    from ttp import ttp

    HAS_TTP = True
except ImportError:
    HAS_TTP = False


class CliParser(CliParserBase):
    """The ttp parser class
    Convert raw text to structured data using ttp
    """

    DEFAULT_TEMPLATE_EXTENSION = "ttp"
    PROVIDE_TEMPLATE_CONTENTS = False

    @staticmethod
    def _check_reqs():
        """Check the prerequisites for the ttp parser

        :return dict: A dict with errors or a template_path
        """
        errors = []

        if not HAS_TTP:
            errors.append(missing_required_lib("ttp"))

        return {"errors": errors}

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
        cli_output = to_native(self._task_args.get("text"), errors="surrogate_then_replace")
        res = self._check_reqs()
        if res.get("errors"):
            return {"errors": res.get("errors")}

        template_path = to_native(
            self._task_args.get("parser").get("template_path"),
            errors="surrogate_then_replace",
        )
        if template_path and not os.path.isfile(template_path):
            return {
                "errors": "error while reading template_path file {file}".format(
                    file=template_path,
                ),
            }

        try:
            parser_param = self._task_args.get("parser")
            vars = (
                parser_param.get("vars", {}).get("ttp_vars", {}) if parser_param.get("vars") else {}
            )
            kwargs = (
                parser_param.get("vars", {}).get("ttp_init", {}) if parser_param.get("vars") else {}
            )
            parser = ttp(data=cli_output, template=template_path, vars=vars, **kwargs)
            parser.parse(one=True)
            ttp_results = (
                parser_param.get("vars", {}).get("ttp_results", {})
                if parser_param.get("vars")
                else {}
            )
            results = parser.result(**ttp_results)
        except Exception as exc:
            msg = "Template Text Parser returned an error while parsing. Error: {err}"
            return {"errors": [msg.format(err=to_native(exc))]}
        return {"parsed": results}
