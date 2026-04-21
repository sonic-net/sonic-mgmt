# Copyright (c) 2012-2013 Michael DeHaan <michael.dehaan@gmail.com>
# Copyright (c) 2016 Toshio Kuratomi <tkuratomi@ansible.com>
# Copyright (c) 2019 Ansible Project
# Copyright (c) 2020 Felix Fontein <felix@fontein.de>
# Copyright (c) 2021 Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this plugin util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

# Parts taken from ansible.module_utils.basic and ansible.module_utils.common.warnings.

# NOTE: THIS IS ONLY FOR ACTION PLUGINS!

from __future__ import annotations

import abc
import copy
import traceback
import typing as t

from ansible.errors import AnsibleError
from ansible.module_utils.basic import remove_values
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.module_utils.errors import UnsupportedError
from ansible.plugins.action import ActionBase


if t.TYPE_CHECKING:
    from ansible_collections.community.crypto.plugins.module_utils._argspec import (
        ArgumentSpec,
    )


class _ModuleExitException(Exception):
    def __init__(self, result: dict[str, t.Any]) -> None:
        super().__init__()
        self.result = result


class AnsibleActionModule:
    def __init__(
        self,
        action_plugin: ActionModuleBase,
        argument_spec: dict[str, t.Any],
        *,
        bypass_checks: bool = False,
        supports_check_mode: bool = False,
        mutually_exclusive: list[list[str] | tuple[str, ...]] | None = None,
        required_together: list[list[str] | tuple[str, ...]] | None = None,
        required_one_of: list[list[str] | tuple[str, ...]] | None = None,
        required_if: list[tuple[str, t.Any, list[str] | tuple[str, ...]]] | None = None,
        required_by: dict[str, tuple[str, ...] | list[str]] | None = None,
    ) -> None:
        # Internal data
        self.__action_plugin = action_plugin
        self.__warnings: list[str] = []
        self.__deprecations: list[dict[str, str | None]] = []

        # AnsibleModule data
        self._name = self.__action_plugin._task.action
        self.argument_spec = argument_spec
        self.supports_check_mode = supports_check_mode
        self.check_mode = self.__action_plugin._play_context.check_mode
        self.bypass_checks = bypass_checks
        self.no_log = self.__action_plugin._play_context.no_log

        self.mutually_exclusive = mutually_exclusive
        self.required_together = required_together
        self.required_one_of = required_one_of
        self.required_if = required_if
        self.required_by = required_by
        self._diff = self.__action_plugin._play_context.diff
        self._verbosity = self.__action_plugin._display.verbosity

        self.params = copy.deepcopy(self.__action_plugin._task.args)
        self.no_log_values = set()
        self._validator = ArgumentSpecValidator(
            self.argument_spec,
            self.mutually_exclusive,
            self.required_together,
            self.required_one_of,
            self.required_if,
            self.required_by,
        )
        self._validation_result = self._validator.validate(self.params)
        self.params.update(self._validation_result.validated_parameters)
        self.no_log_values.update(self._validation_result._no_log_values)

        try:
            error = self._validation_result.errors[0]
        except IndexError:
            error = None

        # We cannot use ModuleArgumentSpecValidator directly since it uses mechanisms for reporting
        # warnings and deprecations that do not work in plugins. This is a copy of that code adjusted
        # for our use-case:
        for d in self._validation_result._deprecations:
            # Before ansible-core 2.14.2, deprecations were always for aliases:
            if "name" in d:
                self.deprecate(
                    f"Alias '{d['name']}' is deprecated. See the module docs for more information",
                    version=d.get("version"),
                    date=d.get("date"),
                    collection_name=d.get("collection_name"),
                )
            # Since ansible-core 2.14.2, a message is present that can be directly printed:
            if "msg" in d:
                self.deprecate(
                    d["msg"],
                    version=d.get("version"),
                    date=d.get("date"),
                    collection_name=d.get("collection_name"),
                )

        for w in self._validation_result._warnings:
            self.warn(f"Both option {w['option']} and its alias {w['alias']} are set.")

        # Fail for validation errors, even in check mode
        if error:
            msg = self._validation_result.errors.msg
            if isinstance(error, UnsupportedError):
                msg = f"Unsupported parameters for ({self._name}) module: {msg}"

            self.fail_json(msg=msg)

    def warn(self, warning: str) -> None:
        # Copied from ansible.module_utils.common.warnings:
        if isinstance(warning, str):
            self.__warnings.append(warning)
        else:
            raise TypeError(f"warn requires a string not a {type(warning)}")

    def deprecate(
        self,
        msg: str,
        version: str | None = None,
        date: str | None = None,
        collection_name: str | None = None,
    ) -> None:
        if version is not None and date is not None:
            raise AssertionError(  # pragma: no cover
                "implementation error -- version and date must not both be set"
            )

        # Copied from ansible.module_utils.common.warnings:
        if not isinstance(msg, str):
            raise TypeError(f"deprecate requires a string not a {type(msg)}")

        # For compatibility, we accept that neither version nor date is set,
        # and treat that the same as if version would haven been set
        if date is not None:
            self.__deprecations.append(
                {"msg": msg, "date": date, "collection_name": collection_name}
            )
        else:
            self.__deprecations.append(
                {"msg": msg, "version": version, "collection_name": collection_name}
            )

    def _return_formatted(self, kwargs: dict[str, t.Any]) -> t.NoReturn:
        if "invocation" not in kwargs:
            kwargs["invocation"] = {"module_args": self.params}

        if self.__warnings:
            kwargs["warnings"] = self.__warnings

        if self.__deprecations:
            kwargs["deprecations"] = self.__deprecations

        kwargs = remove_values(kwargs, self.no_log_values)
        raise _ModuleExitException(kwargs)

    def exit_json(self, **kwargs: t.Any) -> t.NoReturn:
        result = dict(kwargs)
        if "failed" not in result:
            result["failed"] = False
        self._return_formatted(result)

    def fail_json(self, msg: str, **kwargs: t.Any) -> t.NoReturn:
        result = dict(kwargs)
        result["failed"] = True
        result["msg"] = msg
        self._return_formatted(result)


class ActionModuleBase(ActionBase, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def setup_module(self) -> tuple[ArgumentSpec, dict[str, t.Any]]:
        """Return pair (ArgumentSpec, kwargs)."""

    @abc.abstractmethod
    def run_module(self, module: AnsibleActionModule) -> None:
        """Run module code"""
        module.fail_json(msg="Not implemented.")

    def run(
        self, tmp: str | None = None, task_vars: dict[str, t.Any] | None = None
    ) -> dict[str, t.Any]:
        if task_vars is None:
            task_vars = {}

        result = super().run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        try:
            argument_spec, kwargs = self.setup_module()
            module = argument_spec.create_ansible_module_helper(
                AnsibleActionModule, (self,), **kwargs
            )
            self.run_module(module)
            raise AnsibleError(
                "Internal error: action module did not call module.exit_json()"
            )
        except _ModuleExitException as mee:
            result.update(mee.result)
            return result
        except Exception:
            result["failed"] = True
            result["msg"] = "MODULE FAILURE"
            result["exception"] = traceback.format_exc()
            return result


__all__ = ("AnsibleActionModule", "ActionModuleBase")
