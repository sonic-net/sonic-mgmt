# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The action plugin file for validate
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible.errors import AnsibleActionFail, AnsibleError
from ansible.module_utils._text import to_text
from ansible.plugins.action import ActionBase

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    check_argspec,
)
from ansible_collections.ansible.utils.plugins.modules.validate import DOCUMENTATION
from ansible_collections.ansible.utils.plugins.plugin_utils.base.validate import _load_validator


ARGSPEC_CONDITIONALS = {}


class ActionModule(ActionBase):
    """action module"""

    VALIDATE_CLS_NAME = "Validate"
    _requires_connection = False

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._validator_name = None
        self._result = {}

    def _debug(self, name, msg):
        """Output text using ansible's display

        :param msg: The message
        :type msg: str
        """
        msg = "<{phost}> {name} {msg}".format(phost=self._playhost, name=name, msg=msg)
        self._display.vvvv(msg)

    def run(self, tmp=None, task_vars=None):
        """The std execution entry pt for an action plugin

        :param tmp: no longer used
        :type tmp: none
        :param task_vars: The vars provided when the task is run
        :type task_vars: dict
        :return: The results from the parser
        :rtype: dict
        """
        valid, argspec_result, updated_params = check_argspec(
            DOCUMENTATION,
            "validate module",
            schema_conditionals=ARGSPEC_CONDITIONALS,
            **self._task.args,
        )
        if not valid:
            return argspec_result

        self._task_vars = task_vars
        self._playhost = task_vars.get("inventory_hostname") if task_vars else None

        self._validator_engine, validator_result = _load_validator(
            engine=updated_params["engine"],
            data=updated_params["data"],
            criteria=updated_params["criteria"],
            plugin_vars=task_vars,
        )
        if validator_result.get("failed"):
            return validator_result

        try:
            result = self._validator_engine.validate()
        except AnsibleError as exc:
            raise AnsibleActionFail(to_text(exc, errors="surrogate_then_replace"))
        except Exception as exc:
            raise AnsibleActionFail(
                "Unhandled exception from validator '{validator}'. Error: {err}".format(
                    validator=self._validator_engine,
                    err=to_text(exc, errors="surrogate_then_replace"),
                ),
            )

        self._result["msg"] = ""
        if result.get("errors"):
            self._result["errors"] = result["errors"]
            self._result.update({"failed": True})
            if "msg" in result:
                self._result["msg"] = "Validation errors were found.\n" + result["msg"]
            else:
                self._result["msg"] = "Validation errors were found."

        if result.get("warnings", []):
            self._result["warnings"] = result["warnings"]
            if not self._result["msg"]:
                self._result["msg"] = "Non-fatal validation errors were found."

        if not self._result["msg"]:
            self._result["msg"] = "All checks passed."

        return self._result
