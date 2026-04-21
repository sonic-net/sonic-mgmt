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

import re

from ansible.errors import AnsibleConnectionFailure
from ansible_collections.ansible.netcommon.plugins.plugin_utils.terminal_base import TerminalBase


class TerminalModule(TerminalBase):
    terminal_stdout_re = [
        re.compile(rb"[\r\n]*[\w+\-\.:\/\[\]]+(?:\([^\)]+\)){,3}(?:>|#) ?$"),
        re.compile(rb"]]>]]>[\r\n]?"),
    ]

    terminal_stderr_re = [
        re.compile(rb"% ?Error"),
        re.compile(rb"% ?Bad secret"),
        re.compile(rb"% ?This command is not authorized"),
        re.compile(rb"invalid input", re.I),
        re.compile(rb"(?:incomplete|ambiguous) command", re.I),
        re.compile(rb"(?<!\()connection timed out(?!\))", re.I),
        re.compile(rb"[^\r\n]+ not found", re.I),
        re.compile(rb"'[^']' +returned error code: ?\d+"),
        re.compile(rb"Failed to commit", re.I),
        re.compile(rb"show configuration failed \[inheritance\]", re.I),
    ]

    terminal_config_prompt = re.compile(r"^.+\(config(-.*)?\)#$")

    def on_open_shell(self):
        try:
            for cmd in (
                b"terminal length 0",
                b"terminal width 512",
                b"terminal exec prompt no-timestamp",
            ):
                self._exec_cli_command(cmd)
        except AnsibleConnectionFailure:
            raise AnsibleConnectionFailure("unable to set terminal parameters")
