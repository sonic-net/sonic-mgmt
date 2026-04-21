#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The fact_diff plugin code
"""
from __future__ import absolute_import, division, print_function

import difflib
import re

from collections.abc import MutableMapping

from ansible.plugins.callback import CallbackBase


__metaclass__ = type


from ansible.errors import AnsibleFilterError


def _raise_error(msg):
    """Raise an error message, prepend with filter name
    :param msg: The message
    :type msg: str
    :raises: AnsibleError
    """
    error = "Error when using filter plugin 'fact_diff': {msg}".format(msg=msg)
    raise AnsibleFilterError(error)


def fact_diff(before, after, plugin, common):
    """Compare two facts or variables and get a diff.
    :param before: The first fact to be used in the comparison.
    :type before: raw
    :param after: The second fact to be used in the comparison.
    :type after: raw
    :param plugin: The name of the plugin in collection format
    :type plugin: string
    """
    if plugin.get("name") == "ansible.utils.native":
        result = fact_diff_native().run_diff(before, after, plugin, common)
    return result


class fact_diff_native(CallbackBase):
    def _check_valid_regexes(self, skip_lines):
        if skip_lines:
            for idx, regex in enumerate(skip_lines):
                try:
                    skip_lines[idx] = re.compile(regex)
                except re.error as exc:
                    msg = "The regex '{regex}', is not valid. The error was {err}.".format(
                        regex=regex,
                        err=str(exc),
                    )
                    _raise_error(msg)

    def _xform(self, before, after, skip_lines):
        if skip_lines:
            if isinstance(before, str):
                before = before.splitlines()
            if isinstance(after, str):
                after = after.splitlines()
            before = [
                line for line in before if not any(regex.match(str(line)) for regex in skip_lines)
            ]
            after = [
                line for line in after if not any(regex.match(str(line)) for regex in skip_lines)
            ]
        if isinstance(before, list):
            before = "\n".join(map(str, before)) + "\n"
        if isinstance(after, list):
            after = "\n".join(map(str, after)) + "\n"
        return before, after, skip_lines

    def get_fact_diff(self, difflist):
        if not isinstance(difflist, list):
            difflist = [difflist]
        ret = []
        for diff in difflist:
            if "before" in diff and "after" in diff:
                # format complex structures into 'files'
                for x in ["before", "after"]:
                    if isinstance(diff[x], MutableMapping):
                        diff[x] = self._serialize_diff(diff[x])
                    elif diff[x] is None:
                        diff[x] = ""
                if "before_header" in diff:
                    before_header = "before: %s" % diff["before_header"]
                else:
                    before_header = "before"
                if "after_header" in diff:
                    after_header = "after: %s" % diff["after_header"]
                else:
                    after_header = "after"
                before_lines = diff["before"].splitlines(True)
                after_lines = diff["after"].splitlines(True)
                if before_lines and not before_lines[-1].endswith("\n"):
                    before_lines[-1] += "\n\\ No newline at end of file\n"
                if after_lines and not after_lines[-1].endswith("\n"):
                    after_lines[-1] += "\n\\ No newline at end of file\n"
                diff_context = (
                    len(before_lines) if len(before_lines) > len(after_lines) else len(after_lines)
                )
                differ = difflib.unified_diff(
                    before_lines,
                    after_lines,
                    fromfile=before_header,
                    tofile=after_header,
                    fromfiledate="",
                    tofiledate="",
                    n=diff_context,
                )
                difflines = list(differ)
                has_diff = False
                for line in difflines:
                    has_diff = True
                    if diff["common"]:
                        if line.startswith("+") or line.startswith("-"):
                            pass
                        else:
                            ret.append(line)
                    else:
                        ret.append(line)
                if has_diff:
                    ret.append("\n")
            if "prepared" in diff:
                ret.append(diff["prepared"])
        return "".join(ret)

    def run_diff(self, before, after, plugin, common):
        skip_lines = plugin["vars"].get("skip_lines")
        self._check_valid_regexes(skip_lines=skip_lines)
        before, after, skip_lines = self._xform(before, after, skip_lines=skip_lines)
        diff = self.get_fact_diff({"before": before, "after": after, "common": common})
        ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
        diff_text = ansi_escape.sub("", diff)
        result = list(diff_text.splitlines())
        return result
