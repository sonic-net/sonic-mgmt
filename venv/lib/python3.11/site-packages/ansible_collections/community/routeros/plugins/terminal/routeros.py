# Copyright (c) 2016 Red Hat Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import re

from ansible.errors import AnsibleConnectionFailure
from ansible.plugins.terminal import TerminalBase
from ansible.utils.display import Display

display = Display()


class TerminalModule(TerminalBase):

    ansi_re = [
        # check ECMA-48 Section 5.4 (Control Sequences)
        re.compile(br'(\x1b\[\?1h\x1b=)'),
        re.compile(br'((?:\x9b|\x1b\x5b)[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e])'),
        re.compile(br'\x08.')
    ]

    terminal_initial_prompt = [
        br'\x1bZ',
    ]

    terminal_initial_answer = b'\x1b/Z'

    terminal_stdout_re = [
        re.compile(br"\x1b<"),
        re.compile(
            br"((\[[\w\-\.]+\@)|(\r\<(([\w\-\.]*\@)|)))"
            br"[\w\s\-\.\/]+\] ?(<SAFE)?> ?$"),
        re.compile(br"Please press \"Enter\" to continue!"),
        re.compile(br"Do you want to see the software license\? \[Y\/n\]: ?"),
    ]

    terminal_stderr_re = [
        re.compile(br"\nbad command name"),
        re.compile(br"\nno such item"),
        re.compile(br"\ninvalid value for"),
    ]

    def on_open_shell(self):
        prompt = self._get_prompt()
        try:
            if prompt.strip().endswith(b':'):
                self._exec_cli_command(b' ')
            if prompt.strip().endswith(b'!'):
                self._exec_cli_command(b'\n')
        except AnsibleConnectionFailure:
            raise AnsibleConnectionFailure('unable to bypass license prompt')
