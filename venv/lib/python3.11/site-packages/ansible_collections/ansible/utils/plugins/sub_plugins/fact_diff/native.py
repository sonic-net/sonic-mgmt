# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    author: Bradley Thornton (@cidrblock)
    name: native
    short_description: Define configurable options for C(native) sub-plugin of M(ansible.utils.fact_diff) module
    description:
    - This plugin documentation provides the configurable options that can be passed
      to the I(ansible.utils.fact_diff) plugins when I(ansible.utils.native) is used as a value for
      I(name) option of the module.
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: Show the difference in json format
  ansible.utils.fact_diff:
    before: "{{ before }}"
    after: "{{ after }}"
    plugin:
      name: ansible.utils.native
"""

import re

from ansible.plugins.callback import CallbackBase

from ansible_collections.ansible.utils.plugins.plugin_utils.base.fact_diff import FactDiffBase


class FactDiff(FactDiffBase):
    def _check_valid_regexes(self):
        if self._skip_lines:
            self._debug("Checking regex in 'split_lines' for validity")
            for idx, regex in enumerate(self._skip_lines):
                try:
                    self._skip_lines[idx] = re.compile(regex)
                except re.error as exc:
                    msg = "The regex '{regex}', is not valid. The error was {err}.".format(
                        regex=regex,
                        err=str(exc),
                    )
                    self._errors.append(msg)

    def _xform(self):
        if self._skip_lines:
            if isinstance(self._before, str):
                self._debug("'before' is a string, splitting lines")
                self._before = self._before.splitlines()
            if isinstance(self._after, str):
                self._debug("'after' is a string, splitting lines")
                self._after = self._after.splitlines()
            self._before = [
                line
                for line in self._before
                if not any(regex.match(str(line)) for regex in self._skip_lines)
            ]
            self._after = [
                line
                for line in self._after
                if not any(regex.match(str(line)) for regex in self._skip_lines)
            ]
        if isinstance(self._before, list):
            self._debug("'before' is a list, joining with \n")
            self._before = "\n".join(map(str, self._before)) + "\n"
        if isinstance(self._after, list):
            self._debug("'after' is a list, joining with \n")
            self._after = "\n".join(map(str, self._after)) + "\n"

    def diff(self):
        self._after = self._task_args["after"]
        self._before = self._task_args["before"]
        self._errors = []
        self._skip_lines = self._task_args["plugin"]["vars"].get("skip_lines")
        self._check_valid_regexes()
        if self._errors:
            return {"errors": " ".join(self._errors)}
        self._xform()
        diff = CallbackBase()._get_diff({"before": self._before, "after": self._after})
        return {"diff": diff}
