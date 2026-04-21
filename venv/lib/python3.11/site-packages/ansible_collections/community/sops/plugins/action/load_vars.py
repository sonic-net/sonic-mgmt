# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from collections.abc import Sequence, Mapping

from ansible.module_utils.common.text.converters import to_native
from ansible.utils.display import Display

from ansible_collections.community.sops.plugins.module_utils.sops import Sops, get_sops_argument_spec

from ansible_collections.community.sops.plugins.plugin_utils.action_module import ActionModuleBase, ArgumentSpec

try:
    from ansible.template import trust_as_template as _trust_as_template
    HAS_DATATAGGING = True
except ImportError:
    HAS_DATATAGGING = False

display = Display()


def _make_safe(value):
    if HAS_DATATAGGING and isinstance(value, str):
        return _trust_as_template(value)
    return value


class ActionModule(ActionModuleBase):

    def _load(self, filename, module):
        def get_option_value(argument_name):
            return module.params.get(argument_name)

        output = Sops.decrypt(filename, display=display, get_option_value=get_option_value)

        data = self._loader.load(output, file_name=filename, show_content=False)
        if not data:
            data = dict()
        if not isinstance(data, dict):
            # Should not happen with sops-encrypted files
            raise Exception('{0} must be stored as a dictionary/hash'.format(to_native(filename)))
        return data

    def _evaluate(self, value):
        if isinstance(value, str):
            # must come *before* Sequence, as strings are also instances of Sequence
            return self._templar.template(_make_safe(value))
        if isinstance(value, Sequence):
            return [self._evaluate(v) for v in value]
        if isinstance(value, Mapping):
            return dict((k, self._evaluate(v)) for k, v in value.items())
        return value

    def _make_safe(self, value):
        if isinstance(value, str):
            # must come *before* Sequence, as strings are also instances of Sequence
            return _make_safe(value)
        if isinstance(value, Sequence):
            return [self._make_safe(v) for v in value]
        if isinstance(value, Mapping):
            return dict((k, self._make_safe(v)) for k, v in value.items())
        return value

    @staticmethod
    def setup_module():
        argument_spec = ArgumentSpec(
            argument_spec=dict(
                file=dict(type='path', required=True),
                name=dict(type='str'),
                expressions=dict(type='str', default='ignore', choices=['ignore', 'evaluate-on-load', 'lazy-evaluation']),
            ),
        )
        argument_spec.argument_spec.update(get_sops_argument_spec())
        return argument_spec, {}

    def run_module(self, module):
        expressions = module.params['expressions']
        if expressions == 'lazy-evaluation' and not HAS_DATATAGGING:
            module.fail_json(msg='expressions=lazy-evaluation requires ansible-core 2.19+ with Data Tagging support.')

        data = dict()
        files = []
        try:
            filename = self._find_needle('vars', module.params['file'])
            data.update(self._load(filename, module))
            files.append(filename)
        except Exception as e:
            module.fail_json(msg=to_native(e))

        name = module.params['name']
        if name is None:
            value = data
        else:
            value = dict()
            value[name] = data

        if expressions == 'evaluate-on-load':
            value = self._evaluate(value)

        if expressions == 'lazy-evaluation':
            value = self._make_safe(value)

        module.exit_json(
            ansible_included_var_files=files,
            ansible_facts=value,
            _ansible_no_log=True,
        )
