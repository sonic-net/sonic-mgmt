#
# Copyright 2018 Red Hat Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible.utils.display import Display

from ansible_collections.ansible.netcommon.plugins.action.network import (
    ActionModule as ActionNetworkModule,
)


display = Display()


class ActionModule(ActionNetworkModule):
    def run(self, tmp=None, task_vars=None):
        module_name = self._task.action.split(".")[-1]
        self._config_module = True if module_name == "netconf_config" else False
        persistent_connection = self._play_context.connection.split(".")[-1]
        warnings = []

        if persistent_connection != "netconf":
            return {
                "failed": True,
                "msg": "Connection type %s is not valid for %s module. "
                "Valid connection type is netconf." % (self._play_context.connection, module_name),
            }

        result = super(ActionModule, self).run(task_vars=task_vars)
        if warnings:
            if "warnings" in result:
                result["warnings"].extend(warnings)
            else:
                result["warnings"] = warnings
        return result
