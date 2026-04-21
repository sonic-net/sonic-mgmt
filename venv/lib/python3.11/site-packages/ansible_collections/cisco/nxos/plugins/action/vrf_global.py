#
# (c) 2016 Red Hat Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible.module_utils.connection import Connection
from ansible.utils.display import Display
from ansible_collections.ansible.netcommon.plugins.action.network import (
    ActionModule as ActionNetworkModule,
)


display = Display()


class ActionModule(ActionNetworkModule):
    def run(self, tmp=None, task_vars=None):
        del tmp  # tmp no longer has any effect

        module_name = self._task.action.split(".")[-1]
        self._config_module = True if module_name in ["nxos_config", "config"] else False
        persistent_connection = self._play_context.connection.split(".")[-1]

        warnings = []

        if (self._play_context.connection == "httpapi") and module_name in (
            "nxos_file_copy",
            "nxos_nxapi",
        ):
            return {
                "failed": True,
                "msg": f"Connection httpapi is not valid for {module_name} module.",
            }

        if module_name == "nxos_file_copy":
            # when file_pull is enabled, the file_pull_timeout and connect_ssh_port options
            # will override persistent_command_timeout and port
            # this has been kept for backwards compatibility till these options are removed
            if persistent_connection != "network_cli":
                return {
                    "failed": True,
                    "msg": (
                        f"Connection type must be fully qualified name for "
                        f"network_cli connection type, got {self._play_context.connection}"
                    ),
                }

            conn = Connection(self._connection.socket_path)
            persistent_command_timeout = conn.get_option("persistent_command_timeout")
            file_pull = self._task.args.get("file_pull", False)
            file_pull_timeout = self._task.args.get("file_pull_timeout")
            connect_ssh_port = self._task.args.get("connect_ssh_port", 22)

            if file_pull:
                # if file_pull_timeout is explicitly set, use that
                if file_pull_timeout:
                    conn.set_option("persistent_command_timeout", file_pull_timeout)
                # if file_pull_timeout is not set and command_timeout < 300s, bump to 300s.
                elif persistent_command_timeout < 300:
                    conn.set_option("persistent_command_timeout", 300)
                conn.set_option("port", connect_ssh_port)

        if module_name == "nxos_install_os":
            connection = self._connection
            persistent_command_timeout = connection.get_option(
                "persistent_command_timeout",
            )
            persistent_connect_timeout = connection.get_option(
                "persistent_connect_timeout",
            )

            display.vvvv(
                f"PERSISTENT_COMMAND_TIMEOUT is {persistent_command_timeout}",
                self._play_context.remote_addr,
            )
            display.vvvv(
                f"PERSISTENT_CONNECT_TIMEOUT is %s {persistent_connect_timeout}",
                self._play_context.remote_addr,
            )
            if persistent_command_timeout < 600 or persistent_connect_timeout < 600:
                msg = "PERSISTENT_COMMAND_TIMEOUT and PERSISTENT_CONNECT_TIMEOUT"
                msg += " must be set to 600 seconds or higher when using nxos_install_os module."
                msg += " Current persistent_command_timeout setting:" + str(
                    persistent_command_timeout,
                )
                msg += " Current persistent_connect_timeout setting:" + str(
                    persistent_connect_timeout,
                )
                return {"failed": True, "msg": msg}

        if persistent_connection in ("network_cli", "httpapi"):
            if module_name == "nxos_gir":
                conn = Connection(self._connection.socket_path)
                persistent_command_timeout = conn.get_option(
                    "persistent_command_timeout",
                )
                gir_timeout = 200
                if persistent_command_timeout < gir_timeout:
                    conn.set_option("persistent_command_timeout", gir_timeout)
                    msg = f"timeout value extended to %ss for nxos_gir {gir_timeout}"
                    display.warning(msg)

        else:
            return {
                "failed": True,
                "msg": f"Connection type {self._play_context.connection} is not valid for this module",
            }

        result = super(ActionModule, self).run(task_vars=task_vars)
        if warnings:
            if "warnings" in result:
                result["warnings"].extend(warnings)
            else:
                result["warnings"] = warnings
        return result
