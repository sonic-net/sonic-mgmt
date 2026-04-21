"""
xml parser

This is the xml parser for use with the cli_parse module and action plugin
https://github.com/martinblech/xmltodict
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    author: Bradley Thornton (@cidrblock)
    name: xml
    short_description: Define configurable options for C(xml) sub-plugin of M(ansible.utils.cli_parse) module
    description:
    - This plugin documentation provides the configurable options that can be passed
      to the M(ansible.utils.cli_parse) plugins when I(ansible.utils.xml) is used as a value for
      I(name) option.
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: "Run command and parse with xml"
  ansible.utils.cli_parse:
    command: "show interface | xml"
    parser:
      name: ansible.utils.xml
  register: nxos_xml_command

- name: "Pass text and parse with xml"
  ansible.utils.cli_parse:
    text: "{{ lookup('ansible.builtin.file', '/home/user/files/nxos_show_interface.xml') }}"
    parser:
      name: ansible.utils.xml
      os: nxos
  register: nxos_xml_text
"""

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import missing_required_lib

from ansible_collections.ansible.utils.plugins.plugin_utils.base.cli_parser import CliParserBase


try:
    import xmltodict

    HAS_XMLTODICT = True
except ImportError:
    HAS_XMLTODICT = False


class CliParser(CliParserBase):
    """The xml parser class
    Convert an xml string to structured data using xmltodict
    """

    DEFAULT_TEMPLATE_EXTENSION = None
    PROVIDE_TEMPLATE_CONTENTS = False

    @staticmethod
    def _check_reqs():
        """Check the prerequisites for the xml parser"""
        errors = []
        if not HAS_XMLTODICT:
            errors.append(missing_required_lib("xmltodict"))

        return errors

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
        if errors:
            return {"errors": errors}

        cli_output = self._task_args.get("text")

        network_os = self._task_args.get("parser").get("os") or self._task_vars.get(
            "ansible_network_os",
        )
        # the nxos | xml includes a odd garbage line at the end, so remove it
        if not network_os:
            self._debug("network_os value is not set")

        if network_os and "nxos" in network_os:
            splitted = cli_output.splitlines()
            if splitted[-1] == "]]>]]>":
                cli_output = "\n".join(splitted[:-1])

        try:
            parsed = xmltodict.parse(cli_output)
            return {"parsed": parsed}
        except Exception as exc:
            msg = "XML parser returned an error while parsing. Error: {err}"
            return {"errors": [msg.format(err=to_native(exc))]}
