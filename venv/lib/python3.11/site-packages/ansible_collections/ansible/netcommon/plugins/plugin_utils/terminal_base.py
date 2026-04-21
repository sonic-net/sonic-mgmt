#
# (c) 2016 Red Hat Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import re

# Needed to satisfy PluginLoader's required_base_class
from ansible.plugins.terminal import TerminalBase as TerminalBaseBase


class TerminalBase(TerminalBaseBase):
    """
    A base class for implementing cli connections

    .. note:: Unlike most of Ansible, nearly all strings in
        :class:`TerminalBase` plugins are byte strings.  This is because of
        how close to the underlying platform these plugins operate.  Remember
        to mark literal strings as byte string (``b"string"``) and to use
        :func:`~ansible.module_utils.common.text.converters.to_bytes` and
        :func:`~ansible.module_utils.common.text.converters.to_text` to avoid
        unexpected problems.
    """

    #: compiled bytes regular expressions as stdout
    terminal_stdout_re = []

    #: compiled bytes regular expressions as stderr
    terminal_stderr_re = []

    #: compiled bytes regular expressions to remove ANSI codes
    ansi_re = [
        re.compile(rb"\x1b\[\?1h\x1b="),  # CSI ? 1 h ESC =
        re.compile(rb"\x08."),  # [Backspace] .
        re.compile(rb"\x1b\[m"),  # ANSI reset code
    ]

    #: terminal initial prompt
    terminal_initial_prompt = None

    #: terminal initial answer
    terminal_initial_answer = None

    #: Send newline after prompt match
    terminal_inital_prompt_newline = True

    def __init__(self, connection):
        super(TerminalBase, self).__init__(connection)
        self._connection = connection

    def _exec_cli_command(self, cmd, check_rc=True):
        """
        Executes the CLI command on the remote device and returns the output

        :arg cmd: Byte string command to be executed
        """
        return self._connection.exec_command(cmd)

    def _get_prompt(self):
        """
        Returns the current prompt from the device

        :returns: A byte string of the prompt
        """
        return self._connection.get_prompt()

    def on_open_shell(self):
        """Called after the SSH session is established

        This method is called right after the invoke_shell() is called from
        the Paramiko SSHClient instance.  It provides an opportunity to setup
        terminal parameters such as disbling paging for instance.
        """
        pass

    def on_close_shell(self):
        """Called before the connection is closed

        This method gets called once the connection close has been requested
        but before the connection is actually closed.  It provides an
        opportunity to clean up any terminal resources before the shell is
        actually closed
        """
        pass

    def on_become(self, passwd=None):
        """Called when privilege escalation is requested

        :kwarg passwd: String containing the password

        This method is called when the privilege is requested to be elevated
        in the play context by setting become to True.  It is the responsibility
        of the terminal plugin to actually do the privilege escalation such
        as entering `enable` mode for instance
        """
        pass

    def on_unbecome(self):
        """Called when privilege deescalation is requested

        This method is called when the privilege changed from escalated
        (become=True) to non escalated (become=False).  It is the responsibility
        of this method to actually perform the deauthorization procedure
        """
        pass

    def on_authorize(self, passwd=None):
        """Deprecated method for privilege escalation

        :kwarg passwd: String containing the password
        """
        return self.on_become(passwd)

    def on_deauthorize(self):
        """Deprecated method for privilege deescalation"""
        return self.on_unbecome()
