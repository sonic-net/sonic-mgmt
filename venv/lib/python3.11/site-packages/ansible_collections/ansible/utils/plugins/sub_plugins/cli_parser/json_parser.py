"""
json parser

This is the json parser for use with the cli_parse module and action plugin
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    author: Bradley Thornton (@cidrblock)
    name: json
    short_description: Define configurable options for B(json) sub-plugin of M(ansible.utils.cli_parse) module
    description:
    - This plugin documentation provides the configurable options that can be passed
      to the M(ansible.utils.cli_parse) plugins when I(ansible.utils.json) is used as a value for
      I(name) option.
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: "Run command and parse with json"
  ansible.utils.cli_parse:
    command: "show version | json"
    parser:
      name: ansible.utils.json
  register: nxos_json_command

- name: "Load text and parse with json"
  ansible.utils.cli_parse:
    text: "{{ lookup('ansible.builtin.file', './nxos_show_interface_json_text.txt') }}"
    parser:
      name: ansible.utils.json
  register: nxos_json_text
"""

import json

from ansible.module_utils._text import to_native
from ansible.module_utils.six import string_types

from ansible_collections.ansible.utils.plugins.plugin_utils.base.cli_parser import CliParserBase


class CliParser(CliParserBase):
    """The json parser class
    Convert a string containing valid json into an object
    """

    DEFAULT_TEMPLATE_EXTENSION = None
    PROVIDE_TEMPLATE_CONTENTS = False

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
        text = self._task_args.get("text")
        try:
            if not isinstance(text, string_types):
                text = json.dumps(text)
            parsed = json.loads(text)
        except Exception as exc:
            return {"errors": [to_native(exc)]}

        return {"parsed": parsed}
