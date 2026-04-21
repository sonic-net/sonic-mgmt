# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

import typing as t
from collections.abc import Mapping

from ansible.plugins.inventory import BaseInventoryPlugin

class _IncludeFilter(t.TypedDict):
    include: str | bool

class _ExcludeFilter(t.TypedDict):
    exclude: str | bool

Filters = list[_IncludeFilter | _ExcludeFilter]

def parse_filters(
    filters: list[t.Any] | None,
) -> Filters: ...
def filter_host(
    inventory_plugin: BaseInventoryPlugin,
    host: str,
    host_vars: Mapping[str, t.Any],
    filters: Filters,
) -> bool: ...
