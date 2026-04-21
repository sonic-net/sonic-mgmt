"""
textfsm parser

This is the textfsm parser for use with the cli_parse module and action plugin
https://github.com/google/textfsm
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    author: Bradley Thornton (@cidrblock)
    name: textfsm
    short_description: Define configurable options for C(textfsm) sub-plugin of M(ansible.utils.cli_parse) module
    description:
    - This plugin documentation provides the configurable options that can be passed
      to the M(ansible.utils.cli_parse) plugins when I(ansible.utils.textfsm) is used as a value for
      I(name) option.
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: "Run command and parse with textfsm"
  ansible.utils.cli_parse:
    command: "show version"
    parser:
      name: ansible.utils.textfsm
  register: nxos_textfsm_command

- name: "Pass text and command"
  ansible.utils.cli_parse:
    text: "{{ lookup('ansible.builtin.file', '/home/user/files/nxos_show_version.txt') }}"
    parser:
      name: ansible.utils.textfsm
      template_path: "/home/user/templates/nxos_show_version.textfsm"
  register: nxos_textfsm_text
"""

import os

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import missing_required_lib

from ansible_collections.ansible.utils.plugins.plugin_utils.base.cli_parser import CliParserBase


try:
    import textfsm

    HAS_TEXTFSM = True
except ImportError:
    HAS_TEXTFSM = False


class CliParser(CliParserBase):
    """The textfsm parser class
    Convert raw text to structured data using textfsm
    """

    DEFAULT_TEMPLATE_EXTENSION = "textfsm"
    PROVIDE_TEMPLATE_CONTENTS = False

    @staticmethod
    def _check_reqs():
        """Check the prerequisites for the textfsm parser

        :return dict: A dict with errors or a template_path
        """
        errors = []

        if not HAS_TEXTFSM:
            errors.append(missing_required_lib("textfsm"))

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
        cli_output = self._task_args.get("text")
        res = self._check_reqs()
        if res.get("errors"):
            return {"errors": res.get("errors")}

        template_path = self._task_args.get("parser").get("template_path")
        if template_path and not os.path.isfile(template_path):
            return {
                "errors": "error while reading template_path file {file}".format(
                    file=template_path,
                ),
            }
        try:
            template = open(self._task_args.get("parser").get("template_path"))
        except IOError as exc:
            return {"errors": to_native(exc)}

        re_table = textfsm.TextFSM(template)
        fsm_results = re_table.ParseText(cli_output)

        results = list()
        for item in fsm_results:
            results.append(dict(zip(re_table.header, item)))

        return {"parsed": results}
