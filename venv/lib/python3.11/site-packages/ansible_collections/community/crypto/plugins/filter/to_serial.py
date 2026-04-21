# Copyright (c) 2024, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
name: to_serial
short_description: Convert an integer to a colon-separated list of hex numbers
author: Felix Fontein (@felixfontein)
version_added: 2.18.0
description:
  - Converts an integer to a colon-separated list of hex numbers of the form C(00:11:22:33).
options:
  _input:
    description:
      - The non-negative integer to convert.
    type: int
    required: true
seealso:
  - plugin: community.crypto.to_serial
    plugin_type: filter
"""

EXAMPLES = r"""
---
- name: Convert integer to serial number
  ansible.builtin.debug:
    msg: "{{ 1234567 | community.crypto.to_serial }}"
"""

RETURN = r"""
_value:
  description:
    - A colon-separated list of hexadecimal numbers.
    - Letters are upper-case, and all numbers have exactly two digits.
    - The string is never empty. The representation of C(0) is C("00").
  type: string
"""

from collections.abc import Callable

from ansible.errors import AnsibleFilterError

from ansible_collections.community.crypto.plugins.module_utils._serial import to_serial


def to_serial_filter(serial_int: int) -> str:
    if not isinstance(serial_int, int):
        raise AnsibleFilterError(
            f"The input for the community.crypto.to_serial filter must be an integer; got {type(serial_int)} instead"
        )
    if serial_int < 0:
        raise AnsibleFilterError(
            "The input for the community.crypto.to_serial filter must not be negative"
        )
    try:
        return to_serial(serial_int)
    except ValueError as exc:
        raise AnsibleFilterError(str(exc)) from exc


class FilterModule:
    """Ansible jinja2 filters"""

    def filters(self) -> dict[str, Callable]:
        return {
            "to_serial": to_serial_filter,
        }
