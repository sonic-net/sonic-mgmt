# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this plugin util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import typing as t
from subprocess import PIPE, Popen

from ansible.module_utils.common.process import get_bin_path
from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.crypto.plugins.module_utils._gnupg.cli import (
    GPGError,
    GPGRunner,
)


class PluginGPGRunner(GPGRunner):
    def __init__(
        self, *, executable: str | None = None, cwd: str | None = None
    ) -> None:
        if executable is None:
            try:
                executable = get_bin_path("gpg")
            except ValueError as exc:
                raise GPGError(
                    "Cannot find the `gpg` executable on the controller"
                ) from exc
        self.executable = executable
        self.cwd = cwd

    def run_command(
        self, command: list[str], *, check_rc: bool = True, data: bytes | None = None
    ) -> tuple[int, str, str]:
        """
        Run ``[gpg] + command`` and return ``(rc, stdout, stderr)``.

        If ``data`` is not ``None``, it will be provided as stdin.
        The code assumes it is a bytes string.

        Returned stdout and stderr are native Python strings.
        Pass ``check_rc=False`` to allow return codes != 0.

        Raises a ``GPGError`` in case of errors.
        """
        command = [self.executable] + command
        with Popen(
            command, shell=False, cwd=self.cwd, stdin=PIPE, stdout=PIPE, stderr=PIPE
        ) as p:
            stdout, stderr = p.communicate(input=data)
            stdout_n = to_text(stdout, errors="surrogate_or_replace")
            stderr_n = to_text(stderr, errors="surrogate_or_replace")
            if check_rc and p.returncode != 0:
                raise GPGError(
                    f'Running {" ".join(command)} yielded return code {p.returncode} with stdout: "{stdout_n}" and stderr: "{stderr_n}")'
                )
            return t.cast(int, p.returncode), stdout_n, stderr_n


__all__ = ("PluginGPGRunner",)
