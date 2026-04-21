# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import re

from importlib import import_module

from ansible.module_utils._text import to_native
from ansible.plugins.action import ActionBase

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.modules.fact_diff import DOCUMENTATION


class ActionModule(ActionBase):
    """action module"""

    _requires_connection = False

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = True
        self._task_vars = None

    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=DOCUMENTATION,
            schema_format="doc",
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            self._result["failed"] = True
            self._result["msg"] = errors

    def _debug(self, msg):
        """Output text using ansible's display

        :param msg: The message
        :type msg: str
        """
        msg = "<{phost}> [fact_diff][{plugin}] {msg}".format(
            phost=self._playhost,
            plugin=self._plugin,
            msg=msg,
        )
        self._display.vvvv(msg)

    def _load_plugin(self, plugin, directory, class_name):
        """Load a plugin from the fs

        :param plugin: The name of the plugin in collection format
        :type plugin: string
        :param directory: The name of the plugin directory to use
        :type directory: string
        :param class_name: The name of the class to load from the plugin
        :type class_name: string
        :return: An instance of class class_name
        :rtype: class_name
        """
        if len(plugin.split(".")) != 3:
            msg = "Plugin name should be provided as a full name including collection"
            self._result["failed"] = True
            self._result["msg"] = msg
            return None
        cref = dict(zip(["corg", "cname", "plugin"], plugin.split(".")))
        cref.update(directory=directory)
        parserlib = (
            "ansible_collections.{corg}.{cname}.plugins.sub_plugins.{directory}.{plugin}".format(
                **cref,
            )
        )
        try:
            class_obj = getattr(import_module(parserlib), class_name)
            class_instance = class_obj(
                task_args=self._task.args,
                task_vars=self._task_vars,
                debug=self._debug,
            )
            return class_instance
        except Exception as exc:
            self._result["failed"] = True
            self._result["msg"] = "Error loading plugin '{plugin}': {err}".format(
                plugin=plugin,
                err=to_native(exc),
            )
            return None

    def _run_diff(self, plugin_instance):
        try:
            result = plugin_instance.diff()
            if "errors" in result:
                self._result["failed"] = True
                self._result["msg"] = result["errors"]
            return result

        except Exception as exc:
            msg = "Unhandled exception from plugin '{plugin}'. Error: {err}".format(
                plugin=self._task.args["plugin"]["name"],
                err=to_native(exc),
            )
            self._result["failed"] = True
            self._result["msg"] = msg
            return None

    def run(self, tmp=None, task_vars=None):
        self._task.diff = True
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._task_vars = task_vars
        self._playhost = task_vars.get("inventory_hostname")

        self._check_argspec()
        if self._result.get("failed"):
            return self._result

        self._plugin = self._task.args["plugin"]["name"]
        plugin_instance = self._load_plugin(self._plugin, "fact_diff", "FactDiff")
        if self._result.get("failed"):
            return self._result

        result = self._run_diff(plugin_instance)
        if self._result.get("failed"):
            return self._result

        ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
        diff_text = ansi_escape.sub("", result["diff"])
        self._result.update(
            {
                "diff": {"prepared": result["diff"]},
                "changed": bool(result["diff"]),
                "diff_lines": diff_text.splitlines(),
                "diff_text": diff_text,
            },
        )
        return self._result
