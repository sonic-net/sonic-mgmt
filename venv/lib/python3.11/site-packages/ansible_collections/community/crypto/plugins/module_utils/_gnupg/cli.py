# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import abc
import os


class GPGError(Exception):
    pass


class GPGRunner(metaclass=abc.ABCMeta):
    @abc.abstractmethod
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


def get_fingerprint_from_stdout(*, stdout: str) -> str:
    lines = stdout.splitlines(False)
    for line in lines:
        if line.startswith("fpr:"):
            parts = line.split(":")
            if len(parts) <= 9 or not parts[9]:
                raise GPGError(
                    f'Result line "{line}" does not have fingerprint as 10th component'
                )
            return parts[9]
    raise GPGError(f'Cannot extract fingerprint from stdout "{stdout}"')


def get_fingerprint_from_file(*, gpg_runner: GPGRunner, path: str) -> str:
    if not os.path.exists(path):
        raise GPGError(f"{path} does not exist")
    stdout = gpg_runner.run_command(
        [
            "--no-keyring",
            "--with-colons",
            "--import-options",
            "show-only",
            "--import",
            path,
        ],
        check_rc=True,
    )[1]
    return get_fingerprint_from_stdout(stdout=stdout)


def get_fingerprint_from_bytes(*, gpg_runner: GPGRunner, content: bytes) -> str:
    stdout = gpg_runner.run_command(
        [
            "--no-keyring",
            "--with-colons",
            "--import-options",
            "show-only",
            "--import",
            "/dev/stdin",
        ],
        data=content,
        check_rc=True,
    )[1]
    return get_fingerprint_from_stdout(stdout=stdout)


__all__ = (
    "GPGError",
    "GPGRunner",
    "get_fingerprint_from_stdout",
    "get_fingerprint_from_file",
    "get_fingerprint_from_bytes",
)
