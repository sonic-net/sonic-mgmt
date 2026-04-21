# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import ast
import re

from ansible.errors import AnsibleActionFail
from ansible.module_utils._text import to_native
from ansible.module_utils.common._collections_compat import MutableMapping, MutableSequence
from ansible.plugins.action import ActionBase
from jinja2 import Template, TemplateSyntaxError

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.modules.update_fact import DOCUMENTATION


class ActionModule(ActionBase):
    """action module"""

    _requires_connection = False

    def __init__(self, *args, **kwargs):
        """Start here"""
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = True
        self._updates = None
        self._result = None

    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=DOCUMENTATION,
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            raise AnsibleActionFail(errors)

    def _ensure_valid_jinja(self):
        """Ensure each path is jinja valid"""
        errors = []
        for entry in self._task.args["updates"]:
            try:
                Template("{{" + entry["path"] + "}}")
            except TemplateSyntaxError as exc:
                error = (
                    "While processing '{path}' found malformed path."
                    " Ensure syntax follows valid jinja format. The error was:"
                    " {error}"
                ).format(path=entry["path"], error=to_native(exc))
                errors.append(error)
        if errors:
            raise AnsibleActionFail(" ".join(errors))

    @staticmethod
    def _field_split(path):
        """Split the path into it's parts

        :param path: The user provided path
        :type path: str
        :return: the individual parts of the path
        :rtype: list
        """
        que = list(path)
        val = que.pop(0)
        fields = []
        try:
            while True:
                field = ""
                # found a '.', move to the next character
                if val == ".":
                    val = que.pop(0)
                # found a '[', pop until ']' and then get the next
                if val == "[":
                    val = que.pop(0)
                    while val != "]":
                        field += val
                        val = que.pop(0)
                    val = que.pop(0)
                else:
                    while val not in [".", "["]:
                        field += val
                        val = que.pop(0)
                try:
                    # make numbers numbers
                    fields.append(ast.literal_eval(field))
                except Exception:
                    # or strip the quotes
                    fields.append(re.sub("['\"]", "", field))
        except IndexError:
            # pop'ed past the end of the que
            # so add the final field
            try:
                fields.append(ast.literal_eval(field))
            except Exception:
                fields.append(re.sub("['\"]", "", field))
        return fields

    def set_value(self, obj, path, val):
        """Set a value

        :param obj: The object to modify
        :type obj: mutable object
        :param path: The path to where the update should be made
        :type path: list
        :param val: The new value to place at path
        :type val: string, dict, list, bool, etc
        """
        first, rest = path[0], path[1:]
        if rest:
            try:
                new_obj = obj[first]
            except (KeyError, TypeError):
                msg = "Error: the key '{first}' was not found " "in {obj}.".format(
                    obj=obj,
                    first=first,
                )
                raise AnsibleActionFail(msg)
            self.set_value(new_obj, rest, val)
        else:
            if isinstance(obj, MutableMapping):
                if obj.get(first) != val:
                    self._result["changed"] = True
                    obj[first] = val
            elif isinstance(obj, MutableSequence):
                if not isinstance(first, int):
                    msg = (
                        "Error: {obj} is a list, "
                        "but index provided was not an integer: '{first}'"
                    ).format(obj=obj, first=first)
                    raise AnsibleActionFail(msg)
                if first > len(obj):
                    msg = "Error: {obj} not long enough for item #{first} to be set.".format(
                        obj=obj,
                        first=first,
                    )
                    raise AnsibleActionFail(msg)
                if first == len(obj):
                    obj.append(val)
                    self._result["changed"] = True
                else:
                    if obj[first] != val:
                        obj[first] = val
                        self._result["changed"] = True
            else:
                msg = "update_fact can only modify mutable objects."
                raise AnsibleActionFail(msg)

    def run(self, tmp=None, task_vars=None):
        """action entry point"""
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()
        results = set()
        self._ensure_valid_jinja()
        for entry in self._task.args["updates"]:
            parts = self._field_split(entry["path"])
            obj, path = parts[0], parts[1:]
            results.add(obj)
            if obj not in task_vars["vars"]:
                msg = "'{obj}' was not found in the current facts.".format(obj=obj)
                raise AnsibleActionFail(msg)
            retrieved = task_vars["vars"].get(obj)
            if path:
                self.set_value(retrieved, path, entry["value"])
            else:
                if task_vars["vars"][obj] != entry["value"]:
                    task_vars["vars"][obj] = entry["value"]
                    self._result["changed"] = True

        for key in results:
            value = task_vars["vars"].get(key)
            self._result[key] = value
        return self._result
