# (c) 2012-2014, Michael DeHaan <michael.dehaan@gmail.com>
# (c) 2015 Toshio Kuratomi <tkuratomi@ansible.com>
# (c) 2017, Peter Sprygada <psprygad@redhat.com>
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


from ansible import constants as C
from ansible.utils.display import Display
from ansible_collections.ansible.utils.plugins.plugin_utils.connection_base import (
    PersistentConnectionBase,
)


display = Display()


__all__ = ["NetworkConnectionBase"]

BUFSIZE = 65536


class NetworkConnectionBase(PersistentConnectionBase):
    """
    A base class for network-style connections using a sub-plugin.
    """

    def __init__(self, play_context, new_stdin, *args, **kwargs):
        super(NetworkConnectionBase, self).__init__(play_context, new_stdin, *args, **kwargs)
        self._network_os = self._play_context.network_os
        self._sub_plugin = {}
        self._cached_variables = (None, None, None)

    def __getattr__(self, name):
        try:
            return self.__dict__[name]
        except KeyError:
            if not name.startswith("_"):
                plugin = self._sub_plugin.get("obj")
                if plugin:
                    method = getattr(plugin, name, None)
                    if method is not None:
                        return method
            raise AttributeError(
                "'%s' object has no attribute '%s'" % (self.__class__.__name__, name)
            )

    def get_options(self, hostvars=None):
        options = super(NetworkConnectionBase, self).get_options(hostvars=hostvars)

        if self._sub_plugin.get("obj") and self._sub_plugin.get("type") != "external":
            try:
                options.update(self._sub_plugin["obj"].get_options(hostvars=hostvars))
            except AttributeError:
                pass

        return options

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super(NetworkConnectionBase, self).set_options(
            task_keys=task_keys, var_options=var_options, direct=direct
        )
        if self.get_option("persistent_log_messages"):
            warning = (
                "Persistent connection logging is enabled for %s. This will log ALL interactions"
                % self._play_context.remote_addr
            )
            logpath = getattr(C, "DEFAULT_LOG_PATH")
            if logpath is not None:
                warning += " to %s" % logpath
            self.queue_message(
                "warning",
                "%s and WILL NOT redact sensitive configuration like passwords. USE WITH CAUTION!"
                % warning,
            )

        if self._sub_plugin.get("obj") and self._sub_plugin.get("type") != "external":
            try:
                self._sub_plugin["obj"].set_options(
                    task_keys=task_keys, var_options=var_options, direct=direct
                )
            except AttributeError:
                pass
