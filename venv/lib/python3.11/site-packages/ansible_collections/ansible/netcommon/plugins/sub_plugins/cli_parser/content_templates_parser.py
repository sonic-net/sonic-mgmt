"""
content templates parser

This is the content templates parser for use with the cli_parse module and action plugin.
The parser functionality used by the network resource modules is leveraged here.

"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    author: Rohit Thakur (@rohitthakur2590)
    name: content_templates
    short_description: Define configurable options for C(content) sub-plugin of C(cli_parse) module
    description:
    - This plugin documentation provides the configurable options that can be passed
      to the I(ansible.utils.cli_parse) plugins when I(ansible.netcommon.content_templates) is used as a value for
      I(name) option.
    version_added: 1.0.0
"""

EXAMPLES = """
- name: "Run command and parse with content_templates"
  ansible.utils.cli_parse:
    command: "show bgp summary"
    parser:
      name: ansible.netcommon.content_templates
    set_fact: bgp_summary
  register: ios_bgp_health

"""
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.ansible.utils.plugins.plugin_utils.base.cli_parser import CliParserBase

from ansible_collections.ansible.netcommon.plugins.module_utils.cli_parser.cli_parsertemplate import (
    CliParserTemplate,
)


class CliParser(CliParserBase):
    """The content_templates parser class
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

        template_contents = kwargs["template_contents"]
        parser = CliParserTemplate(lines=self._task_args.get("text", "").splitlines())
        try:
            template_obj = list(eval(template_contents))
        except Exception as exc:
            return {"errors": [to_native(exc)]}

        try:
            parser.PARSERS = template_obj
            out = {"parsed": parser.parse()}
            return out
        except Exception as exc:
            msg = "An error occurred during content_templates parsing. Error: {err}"
            return {"errors": [msg.format(err=to_native(exc))]}
