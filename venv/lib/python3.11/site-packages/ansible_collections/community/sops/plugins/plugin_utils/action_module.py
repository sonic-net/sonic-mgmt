# Copyright (c) 2012-2013 Michael DeHaan <michael.dehaan@gmail.com>
# Copyright (c) 2016 Toshio Kuratomi <tkuratomi@ansible.com>
# Copyright (c) 2019 Ansible Project
# Copyright (c) 2020 Felix Fontein <felix@fontein.de>
# Copyright (c) 2021 Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Parts taken from ansible.module_utils.basic and ansible.module_utils.common.warnings.

# NOTE: THIS IS ONLY FOR ACTION PLUGINS!

from __future__ import annotations


import abc
import copy
import traceback

from ansible.errors import AnsibleError
from ansible.module_utils.basic import SEQUENCETYPE, remove_values
from collections.abc import Mapping
from ansible.plugins.action import ActionBase

from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.module_utils.errors import UnsupportedError

try:
    from ansible.module_utils.common.validation import (
        safe_eval,
    )
except ImportError:
    safe_eval = None


class _ModuleExitException(Exception):
    def __init__(self, result):
        super().__init__()
        self.result = result


class AnsibleActionModule:
    def __init__(self, action_plugin, argument_spec, bypass_checks=False,
                 mutually_exclusive=None, required_together=None,
                 required_one_of=None, supports_check_mode=False,
                 required_if=None, required_by=None):
        # Internal data
        self.__action_plugin = action_plugin
        self.__warnings = []
        self.__deprecations = []

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

        self.aliases = {}
        self._legal_inputs = []
        self._options_context = list()

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
            if 'name' in d:
                self.deprecate(
                    "Alias '{name}' is deprecated. See the module docs for more information".format(name=d['name']),
                    version=d.get('version'), date=d.get('date'), collection_name=d.get('collection_name'))
            # Since ansible-core 2.14.2, a message is present that can be directly printed:
            if 'msg' in d:
                self.deprecate(d['msg'], version=d.get('version'), date=d.get('date'), collection_name=d.get('collection_name'))

        for w in self._validation_result._warnings:
            self.warn('Both option {option} and its alias {alias} are set.'.format(option=w['option'], alias=w['alias']))

        # Fail for validation errors, even in check mode
        if error:
            msg = self._validation_result.errors.msg
            if isinstance(error, UnsupportedError):
                msg = "Unsupported parameters for ({name}) {kind}: {msg}".format(name=self._name, kind='module', msg=msg)

            self.fail_json(msg=msg)

    def safe_eval(self, value, locals=None, include_exceptions=False):
        if safe_eval is None:
            raise ValueError("safe_eval is not available since ansible-core 2.21")
        return safe_eval(value, locals, include_exceptions)

    def warn(self, warning):
        # Copied from ansible.module_utils.common.warnings:
        if isinstance(warning, str):
            self.__warnings.append(warning)
        else:
            raise TypeError("warn requires a string not a %s" % type(warning))

    def deprecate(self, msg, version=None, date=None, collection_name=None):
        if version is not None and date is not None:
            raise AssertionError("implementation error -- version and date must not both be set")

        # Copied from ansible.module_utils.common.warnings:
        if isinstance(msg, str):
            # For compatibility, we accept that neither version nor date is set,
            # and treat that the same as if version would haven been set
            if date is not None:
                self.__deprecations.append({'msg': msg, 'date': date, 'collection_name': collection_name})
            else:
                self.__deprecations.append({'msg': msg, 'version': version, 'collection_name': collection_name})
        else:
            raise TypeError("deprecate requires a string not a %s" % type(msg))

    def _return_formatted(self, kwargs):
        if 'invocation' not in kwargs:
            kwargs['invocation'] = {'module_args': self.params}

        if 'warnings' in kwargs:
            if isinstance(kwargs['warnings'], list):
                for w in kwargs['warnings']:
                    self.warn(w)
            else:
                self.warn(kwargs['warnings'])

        if self.__warnings:
            kwargs['warnings'] = self.__warnings

        if 'deprecations' in kwargs:
            if isinstance(kwargs['deprecations'], list):
                for d in kwargs['deprecations']:
                    if isinstance(d, SEQUENCETYPE) and len(d) == 2:
                        self.deprecate(d[0], version=d[1])
                    elif isinstance(d, Mapping):
                        self.deprecate(d['msg'], version=d.get('version'), date=d.get('date'),
                                       collection_name=d.get('collection_name'))
                    else:
                        self.deprecate(d)  # pylint: disable=ansible-deprecated-no-version
            else:
                self.deprecate(kwargs['deprecations'])  # pylint: disable=ansible-deprecated-no-version

        if self.__deprecations:
            kwargs['deprecations'] = self.__deprecations

        kwargs = remove_values(kwargs, self.no_log_values)
        raise _ModuleExitException(kwargs)

    def exit_json(self, **kwargs):
        result = dict(kwargs)
        if 'failed' not in result:
            result['failed'] = False
        self._return_formatted(result)

    def fail_json(self, msg, **kwargs):
        result = dict(kwargs)
        result['failed'] = True
        result['msg'] = msg
        self._return_formatted(result)


class ActionModuleBase(ActionBase, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def setup_module(self):
        """Return pair (ArgumentSpec, kwargs)."""
        pass

    @abc.abstractmethod
    def run_module(self, module):
        """Run module code"""
        module.fail_json(msg='Not implemented.')

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = dict()

        result = super().run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        try:
            argument_spec, kwargs = self.setup_module()
            module = argument_spec.create_ansible_module_helper(AnsibleActionModule, (self, ), **kwargs)
            self.run_module(module)
            raise AnsibleError('Internal error: action module did not call module.exit_json()')
        except _ModuleExitException as mee:
            result.update(mee.result)
            return result
        except Exception as dummy:
            result['failed'] = True
            result['msg'] = 'MODULE FAILURE'
            result['exception'] = traceback.format_exc()
            return result


class ArgumentSpec:
    def __init__(self, argument_spec, mutually_exclusive=None, required_together=None, required_one_of=None, required_if=None, required_by=None):
        self.argument_spec = argument_spec
        self.mutually_exclusive = mutually_exclusive or []
        self.required_together = required_together or []
        self.required_one_of = required_one_of or []
        self.required_if = required_if or []
        self.required_by = required_by or {}

    def create_ansible_module_helper(self, clazz, args, **kwargs):
        return clazz(
            *args,
            argument_spec=self.argument_spec,
            mutually_exclusive=self.mutually_exclusive,
            required_together=self.required_together,
            required_one_of=self.required_one_of,
            required_if=self.required_if,
            required_by=self.required_by,
            **kwargs)
