# Copyright (c) 2022 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this plugin util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

# NOTE: THIS IS ONLY FOR FILTER PLUGINS!

from __future__ import annotations

import typing as t

from ansible.errors import AnsibleFilterError
from ansible.utils.display import Display


_display = Display()


class FilterModuleMock:
    def __init__(self, params: dict[str, t.Any]) -> None:
        self.check_mode = True
        self.params = params
        self._diff = False

    def fail_json(self, msg: str, **kwargs: t.Any) -> t.NoReturn:
        raise AnsibleFilterError(msg)

    def warn(self, warning: str) -> None:
        _display.warning(warning)


__all__ = ("FilterModuleMock",)
