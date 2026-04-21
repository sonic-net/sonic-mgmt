# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import typing as t
from collections.abc import Callable

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_text
from ansible_collections.community.dns.plugins.plugin_utils.public_suffix import (
    PUBLIC_SUFFIX_LIST,
)


def _remove_suffix(dns_name: str, suffix: str, keep_trailing_period: bool) -> str:
    suffix_len = len(suffix)
    if suffix_len and suffix_len < len(dns_name) and not keep_trailing_period:
        suffix_len += 1
    return dns_name[:-suffix_len] if suffix_len else dns_name


def get_registrable_domain(
    dns_name: t.Any,
    keep_unknown_suffix: t.Any = True,
    only_if_registerable: t.Any = True,
    normalize_result: t.Any = False,
    icann_only: t.Any = False,
) -> str:
    """Given DNS name, returns the registrable domain."""
    if not isinstance(dns_name, (str, bytes)):
        raise AnsibleFilterError(
            "Input for community.dns.get_registrable_domain must be a string"
        )
    for parameter, value in [
        ("keep_unknown_suffix", keep_unknown_suffix),
        ("only_if_registerable", only_if_registerable),
        ("normalize_result", normalize_result),
        ("icann_only", icann_only),
    ]:
        if not isinstance(value, bool):
            raise AnsibleFilterError(f"{parameter} must be a boolean, not {value!r}")
    return PUBLIC_SUFFIX_LIST.get_registrable_domain(
        to_text(dns_name),
        keep_unknown_suffix=keep_unknown_suffix,
        only_if_registerable=only_if_registerable,
        normalize_result=normalize_result,
        icann_only=icann_only,
    )


def get_public_suffix(
    dns_name: t.Any,
    keep_leading_period: t.Any = True,
    keep_unknown_suffix: t.Any = True,
    normalize_result: t.Any = False,
    icann_only: t.Any = False,
) -> str:
    """Given DNS name, returns the public suffix."""
    if not isinstance(dns_name, (str, bytes)):
        raise AnsibleFilterError(
            "Input for community.dns.get_registrable_domain must be a string"
        )
    for parameter, value in [
        ("keep_leading_period", keep_leading_period),
        ("keep_unknown_suffix", keep_unknown_suffix),
        ("normalize_result", normalize_result),
        ("icann_only", icann_only),
    ]:
        if not isinstance(value, bool):
            raise AnsibleFilterError(f"{parameter} must be a boolean, not {value!r}")
    suffix = PUBLIC_SUFFIX_LIST.get_suffix(
        to_text(dns_name),
        keep_unknown_suffix=keep_unknown_suffix,
        normalize_result=normalize_result,
        icann_only=icann_only,
    )
    if suffix and len(suffix) < len(dns_name) and keep_leading_period:
        suffix = "." + suffix
    return suffix


def remove_registrable_domain(
    dns_name: t.Any,
    keep_trailing_period: t.Any = False,
    keep_unknown_suffix: t.Any = True,
    only_if_registerable: t.Any = True,
    icann_only: t.Any = False,
) -> str:
    """Given DNS name, returns the part before the registrable_domain."""
    if not isinstance(dns_name, (str, bytes)):
        raise AnsibleFilterError(
            "Input for community.dns.get_registrable_domain must be a string"
        )
    for parameter, value in [
        ("keep_trailing_period", keep_trailing_period),
        ("keep_unknown_suffix", keep_unknown_suffix),
        ("only_if_registerable", only_if_registerable),
        ("icann_only", icann_only),
    ]:
        if not isinstance(value, bool):
            raise AnsibleFilterError(f"{parameter} must be a boolean, not {value!r}")
    dns_name = to_text(dns_name)
    suffix = PUBLIC_SUFFIX_LIST.get_registrable_domain(
        dns_name,
        keep_unknown_suffix=keep_unknown_suffix,
        only_if_registerable=only_if_registerable,
        normalize_result=False,
        icann_only=icann_only,
    )
    return _remove_suffix(dns_name, suffix, keep_trailing_period)


def remove_public_suffix(
    dns_name: t.Any,
    keep_trailing_period: t.Any = False,
    keep_unknown_suffix: t.Any = True,
    icann_only: t.Any = False,
) -> str:
    """Given DNS name, returns the part before the public suffix."""
    if not isinstance(dns_name, (str, bytes)):
        raise AnsibleFilterError(
            "Input for community.dns.get_registrable_domain must be a string"
        )
    for parameter, value in [
        ("keep_trailing_period", keep_trailing_period),
        ("keep_unknown_suffix", keep_unknown_suffix),
        ("icann_only", icann_only),
    ]:
        if not isinstance(value, bool):
            raise AnsibleFilterError(f"{parameter} must be a boolean, not {value!r}")
    dns_name = to_text(dns_name)
    suffix = PUBLIC_SUFFIX_LIST.get_suffix(
        dns_name,
        keep_unknown_suffix=keep_unknown_suffix,
        normalize_result=False,
        icann_only=icann_only,
    )
    return _remove_suffix(dns_name, suffix, keep_trailing_period)


class FilterModule:
    """Ansible jinja2 filters"""

    def filters(self) -> dict[str, Callable]:
        return {
            "get_public_suffix": get_public_suffix,
            "get_registrable_domain": get_registrable_domain,
            "remove_public_suffix": remove_public_suffix,
            "remove_registrable_domain": remove_registrable_domain,
        }
