# Copyright (c) 2024, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
name: parse_serial
short_description: Convert a serial number as a colon-separated list of hex numbers to an integer
author: Felix Fontein (@felixfontein)
version_added: 2.18.0
description:
  - Parses a colon-separated list of hex numbers of the form C(00:11:22:33) and returns the corresponding integer.
options:
  _input:
    description:
      - A serial number represented as a colon-separated list of hex numbers between 0 and 255.
      - These numbers are interpreted as the byte presentation of an unsigned integer in network byte order. That is, C(01:00)
        is interpreted as the integer 256.
    type: string
    required: true
seealso:
  - plugin: community.crypto.to_serial
    plugin_type: filter
"""

EXAMPLES = r"""
---
- name: Parse serial number
  ansible.builtin.debug:
    msg: "{{ '11:22:33' | community.crypto.parse_serial }}"
"""

RETURN = r"""
_value:
  description:
    - The serial number as an integer.
  type: int
"""

from collections.abc import Callable

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.crypto.plugins.module_utils._serial import (
    parse_serial,
)


def parse_serial_filter(serial_str: str | bytes) -> int:
    if not isinstance(serial_str, (str, bytes)):
        raise AnsibleFilterError(
            f"The input for the community.crypto.parse_serial filter must be a string; got {type(serial_str)} instead"
        )
    try:
        return parse_serial(to_text(serial_str))
    except ValueError as exc:
        raise AnsibleFilterError(str(exc)) from exc


class FilterModule:
    """Ansible jinja2 filters"""

    def filters(self) -> dict[str, Callable]:
        return {
            "parse_serial": parse_serial_filter,
        }
