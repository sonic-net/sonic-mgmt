# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    author: Katherine Case (@Qalthos)
    name: config
    short_description: Define configurable options for configuration validate plugin
    description:
    - This sub plugin documentation provides the configurable options that can be passed
      to the validate plugins when C(ansible.utils.config) is used as a value for
      engine option.
    version_added: 2.1.0
    notes:
    - The value of I(data) option should be a candidate device configuration.
    - The value of I(criteria) should be a B(list) of rules the candidate configuration
      will be checked against, or a yaml document containing those rules.
"""


EXAMPLES = r"""
- name: Interface description should not be more than 8 chars
  example: "Matches description this-is-a-long-description"
  rule: 'description\s(.{9,})'
  action: warn

- name: Ethernet interface names should be in format Ethernet[Slot/chassis number].[sub-intf number (optional)]
  example: "Matches interface Eth1/1, interface Eth 1/1, interface Ethernet 1/1, interface Ethernet 1/1.100"
  rule: 'interface\s[eE](?!\w{7}\d/\d(.\d+)?)'
  action: fail

- name: Loopback interface names should be in format loopback[Virtual Interface Number]
  example: "Matches interface Lo10, interface Loopback 10"
  rule: 'interface\s[lL](?!\w{7}\d)'
  action: fail

- name: Port Channel names should be in format port-channel[Port Channel number].[sub-intf number (optional)]
  example: "Matches interface port-channel 10, interface po10, interface port-channel 10.1"
  rule: 'interface\s[pP](?!\w{3}-\w{7}\d(.\d+)?)'
  action: fail
"""

import re

from io import StringIO

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_text
from ansible.module_utils.six import string_types

from ansible_collections.ansible.utils.plugins.module_utils.common.utils import to_list
from ansible_collections.ansible.utils.plugins.plugin_utils.base.validate import ValidateBase


try:
    import yaml

    # use C version if possible for speedup
    try:
        from yaml import CSafeLoader as SafeLoader
    except ImportError:
        from yaml import SafeLoader
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def format_message(match, line_number, criteria):
    """Format warning or error message based on given line and criteria."""
    return 'At line {line_number}: {message}\nFound "{line}"'.format(
        line_number=line_number + 1,
        message=criteria["name"],
        line=match.string,
    )


class Validate(ValidateBase):
    def _check_args(self):
        """Ensure specific args are set

        :return: None: In case all arguments passed are valid
        """

        try:
            if isinstance(self._criteria, string_types):
                self._criteria = yaml.load(StringIO(self._criteria), Loader=SafeLoader)
        except yaml.parser.ParserError as exc:
            msg = (
                "'criteria' option value is invalid, value should be valid YAML."
                " Failed to read with error '{err}'".format(
                    err=to_text(exc, errors="surrogate_then_replace"),
                )
            )
            raise AnsibleError(msg)

        issues = []
        for item in to_list(self._criteria):
            if "name" not in item:
                issues.append('Criteria {item} missing "name" key'.format(item=item))
            if "action" not in item:
                issues.append('Criteria {item} missing "action" key'.format(item=item))
            elif item["action"] not in ("warn", "fail"):
                issues.append(
                    'Action in criteria {item} is not one of "warn" or "fail"'.format(
                        item=item,
                    ),
                )
            if "rule" not in item:
                issues.append('Criteria {item} missing "rule" key'.format(item=item))
            else:
                try:
                    item["rule"] = re.compile(item["rule"])
                except re.error as exc:
                    issues.append(
                        'Failed to compile regex "{rule}": {exc}'.format(
                            rule=item["rule"],
                            exc=exc,
                        ),
                    )

        if issues:
            msg = "\n".join(issues)
            raise AnsibleError(msg)

    def validate(self):
        """Std entry point for a validate execution

        :return: Errors or parsed text as structured data
        :rtype: dict

        :example:

        The parse function of a parser should return a dict:
        {"errors": [a list of errors]}
        or
        {"parsed": obj}
        """
        self._check_args()

        try:
            self._validate_config()
        except Exception as exc:
            return {"errors": to_text(exc, errors="surrogate_then_replace")}

        return self._result

    def _validate_config(self):
        warnings = []
        errors = []
        error_messages = []

        for criteria in self._criteria:
            for line_number, line in enumerate(self._data.split("\n")):
                match = criteria["rule"].search(line)
                if match:
                    if criteria["action"] == "warn":
                        warnings.append(format_message(match, line_number, criteria))
                    if criteria["action"] == "fail":
                        errors.append({"message": criteria["name"], "found": line})
                        error_messages.append(
                            format_message(match, line_number, criteria),
                        )

        if errors:
            if "errors" not in self._result:
                self._result["errors"] = []
            self._result["errors"].extend(errors)
        if error_messages:
            if "msg" not in self._result:
                self._result["msg"] = "\n".join(error_messages)
            else:
                self._result["msg"] += "\n".join(error_messages)
        if warnings:
            if "warnings" not in self._result:
                self._result["warnings"] = []
            self._result["warnings"].extend(warnings)
