# (c) 2012-2014, Michael DeHaan <michael.dehaan@gmail.com>
# (c) 2015 Toshio Kuratomi <tkuratomi@ansible.com>
# (c) 2017, Peter Sprygada <psprygad@redhat.com>
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import os

from ansible import constants as C
from ansible.plugins.connection import ConnectionBase
from ansible.plugins.loader import connection_loader
from ansible.utils.display import Display
from ansible.utils.path import unfrackpath


display = Display()


__all__ = ["PersistentConnectionBase"]


class PersistentConnectionBase(ConnectionBase):
    """
    A base for simple persistent connections.
    """

    force_persistence = True
    # Do not use _remote_is_local in other connections
    _remote_is_local = True

    def __init__(self, play_context, new_stdin, *args, **kwargs):
        super(PersistentConnectionBase, self).__init__(play_context, new_stdin, *args, **kwargs)
        self._messages = []
        self._conn_closed = False

        self._local = connection_loader.get("local", play_context, "/dev/null")
        self._local.set_options()

        # reconstruct the socket_path and set instance values accordingly
        self._ansible_playbook_pid = kwargs.get("ansible_playbook_pid")
        self._update_connection_state()

    def exec_command(self, cmd, in_data=None, sudoable=True):
        return self._local.exec_command(cmd, in_data, sudoable)

    def queue_message(self, level, message):
        """
        Adds a message to the queue of messages waiting to be pushed back to the controller process.

        :arg level: A string which can either be the name of a method in display, or 'log'. When
            the messages are returned to task_executor, a value of log will correspond to
            ``display.display(message, log_only=True)``, while another value will call ``display.[level](message)``
        """
        self._messages.append((level, message))

    def pop_messages(self):
        messages, self._messages = self._messages, []
        return messages

    def put_file(self, in_path, out_path):
        """Transfer a file from local to remote"""
        return self._local.put_file(in_path, out_path)

    def fetch_file(self, in_path, out_path):
        """Fetch a file from remote to local"""
        return self._local.fetch_file(in_path, out_path)

    def reset(self):
        """
        Reset the connection
        """
        if self._socket_path:
            self.queue_message(
                "vvvv",
                "resetting persistent connection for socket_path %s" % self._socket_path,
            )
            self.close()
        self.queue_message("vvvv", "reset call on connection instance")

    def close(self):
        self._conn_closed = True
        if self._connected:
            self._connected = False

    def _update_connection_state(self):
        """
        Reconstruct the connection socket_path and check if it exists

        If the socket path exists then the connection is active and set
        both the _socket_path value to the path and the _connected value
        to True.  If the socket path doesn't exist, leave the socket path
        value to None and the _connected value to False
        """
        ssh = connection_loader.get("ssh", class_only=True)
        control_path = ssh._create_control_path(
            self._play_context.remote_addr,
            self._play_context.port,
            self._play_context.remote_user,
            self._play_context.connection,
            self._ansible_playbook_pid,
        )

        tmp_path = unfrackpath(C.PERSISTENT_CONTROL_PATH_DIR)
        socket_path = unfrackpath(control_path % dict(directory=tmp_path))

        if os.path.exists(socket_path):
            self._connected = True
            self._socket_path = socket_path

    def _log_messages(self, message):
        if self.get_option("persistent_log_messages"):
            self.queue_message("log", message)
