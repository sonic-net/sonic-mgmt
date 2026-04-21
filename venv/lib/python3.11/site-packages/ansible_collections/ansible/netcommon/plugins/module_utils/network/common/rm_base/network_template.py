# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2021 Red Hat Inc.
#
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import re

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module_base import (
    RmEngineBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    Template,
    dict_merge,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    validate_config as _validate_config,
)


try:
    from ansible.module_utils.common.parameters import _list_no_log_values as list_no_log_values
except ImportError:
    # TODO: Remove this import when we no longer support ansible < 2.11
    from ansible.module_utils.common.parameters import list_no_log_values


class NetworkTemplate(RmEngineBase):
    """The NetworkTemplate class that Resource Module templates
    inherit and use to parse and render config lines.
    """

    def __init__(self, lines=None, tmplt=None, prefix=None, module=None):
        super(NetworkTemplate, self).__init__(module=module)
        self._lines = lines or []
        self._tmplt = tmplt
        self._template = Template()
        self._prefix = prefix or {}

    def _deepformat(self, tmplt, data):
        wtmplt = deepcopy(tmplt)
        if isinstance(tmplt, str):
            res = self._template(value=tmplt, variables=data, fail_on_undefined=False)
            return res
        if isinstance(tmplt, dict):
            for tkey, tval in tmplt.items():
                ftkey = self._template(tkey, data)
                if ftkey != tkey:
                    wtmplt.pop(tkey)
                if isinstance(tval, dict):
                    wtmplt[ftkey] = self._deepformat(tval, data)
                elif isinstance(tval, list):
                    wtmplt[ftkey] = [self._deepformat(x, data) for x in tval]
                elif isinstance(tval, str):
                    wtmplt[ftkey] = self._deepformat(tval, data)
                    if wtmplt[ftkey] is None:
                        wtmplt.pop(ftkey)
        return wtmplt

    def parse(self):
        """parse"""
        result = {}
        shared = {}
        for line in self._lines:
            for parser in self._tmplt.PARSERS:
                cap = re.match(parser["getval"], line)
                if cap:
                    capdict = cap.groupdict()
                    capdict = dict((k, v) for k, v in capdict.items() if v is not None)
                    if parser.get("shared"):
                        shared = capdict
                    vals = dict_merge(capdict, shared)
                    res = self._deepformat(deepcopy(parser["result"]), vals)
                    result = dict_merge(result, res)
                    break
        return result

    def get_parser(self, name):
        """get_parsers"""
        res = [p for p in self._tmplt.PARSERS if p["name"] == name]
        return res[0]

    def _render(self, tmplt, data, negate):
        try:
            if callable(tmplt):
                res = tmplt(data)
            else:
                res = self._template(value=tmplt, variables=data, fail_on_undefined=False)
        except KeyError:
            return None

        if res:
            if negate:
                rem = "{0} ".format(self._prefix.get("remove", "no"))
                if isinstance(res, list):
                    cmd = [(rem + each) for each in res]
                    return cmd
                return rem + res
            elif self._prefix.get("set"):
                set_cmd = "{0} ".format(self._prefix.get("set", ""))
                if isinstance(res, list):
                    cmd = [(set_cmd + each) for each in res]
                    return cmd
                return set_cmd + res
        return res

    def render(self, data, parser_name, negate=False):
        """render"""
        if negate:
            tmplt = (
                self.get_parser(parser_name).get("remval") or self.get_parser(parser_name)["setval"]
            )
        else:
            tmplt = self.get_parser(parser_name)["setval"]
        command = self._render(tmplt, data, negate)
        return command

    def validate_config(self, spec, data, redact=False):
        validated_data = _validate_config(spec, data)
        if redact:
            self._module.no_log_values.update(list_no_log_values(spec, validated_data))
        return validated_data
