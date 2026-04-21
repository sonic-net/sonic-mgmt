# (c) 2022 Red Hat Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

from functools import total_ordering


@total_ordering
class Version:
    """Simple class to compare arbitrary versions"""

    def __init__(self, version_string):
        self.components = version_string.split(".")

    def __eq__(self, other):
        other = _coerce(other)
        if not isinstance(other, Version):
            return NotImplemented

        return self.components == other.components

    def __lt__(self, other):
        other = _coerce(other)
        if not isinstance(other, Version):
            return NotImplemented

        return self.components < other.components


def _coerce(other):
    if isinstance(other, str):
        other = Version(other)
    if isinstance(other, (int, float)):
        other = Version(str(other))
    return other
