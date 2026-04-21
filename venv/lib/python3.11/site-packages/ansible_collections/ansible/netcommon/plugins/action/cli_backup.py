#
# Copyright 2018 Red Hat Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible_collections.ansible.netcommon.plugins.action.network import (
    ActionModule as ActionNetworkModule,
)


class ActionModule(ActionNetworkModule):
    def run(self, tmp=None, task_vars=None):
        if self._play_context.connection.split(".")[-1] != "network_cli":
            return {
                "failed": True,
                "msg": "Connection type %s is not valid for this module"
                % self._play_context.connection,
            }
        result = super(ActionModule, self).run(task_vars=task_vars)
        self._handle_backup_option(
            result,
            task_vars,
            self._task.args,
        )

        return result
