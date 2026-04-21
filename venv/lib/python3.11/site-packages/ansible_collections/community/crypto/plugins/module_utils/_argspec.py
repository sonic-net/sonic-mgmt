# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import typing as t

from ansible.module_utils.basic import AnsibleModule


_T = t.TypeVar("_T")


def _ensure_list(value: list[_T] | tuple[_T] | None) -> list[_T]:
    if value is None:
        return []
    return list(value)


class ArgumentSpec:
    def __init__(
        self,
        argument_spec: dict[str, t.Any] | None = None,
        *,
        mutually_exclusive: list[list[str] | tuple[str, ...]] | None = None,
        required_together: list[list[str] | tuple[str, ...]] | None = None,
        required_one_of: list[list[str] | tuple[str, ...]] | None = None,
        required_if: (
            list[
                tuple[str, t.Any, list[str] | tuple[str, ...]]
                | tuple[str, t.Any, list[str] | tuple[str, ...], bool]
            ]
            | None
        ) = None,
        required_by: dict[str, tuple[str, ...] | list[str]] | None = None,
    ) -> None:
        self.argument_spec = argument_spec or {}
        self.mutually_exclusive = _ensure_list(mutually_exclusive)
        self.required_together = _ensure_list(required_together)
        self.required_one_of = _ensure_list(required_one_of)
        self.required_if = _ensure_list(required_if)
        self.required_by = required_by or {}

    def update_argspec(self, **kwargs: t.Any) -> t.Self:
        self.argument_spec.update(kwargs)
        return self

    def update(
        self,
        *,
        mutually_exclusive: list[list[str] | tuple[str, ...]] | None = None,
        required_together: list[list[str] | tuple[str, ...]] | None = None,
        required_one_of: list[list[str] | tuple[str, ...]] | None = None,
        required_if: (
            list[
                tuple[str, t.Any, list[str] | tuple[str, ...]]
                | tuple[str, t.Any, list[str] | tuple[str, ...], bool]
            ]
            | None
        ) = None,
        required_by: dict[str, tuple[str, ...] | list[str]] | None = None,
    ) -> t.Self:
        if mutually_exclusive:
            self.mutually_exclusive.extend(mutually_exclusive)
        if required_together:
            self.required_together.extend(required_together)
        if required_one_of:
            self.required_one_of.extend(required_one_of)
        if required_if:
            self.required_if.extend(required_if)
        if required_by:
            for k, v in required_by.items():
                if k in self.required_by:
                    v = list(self.required_by[k]) + list(v)
                self.required_by[k] = v
        return self

    def merge(self, other: t.Self) -> t.Self:
        self.update_argspec(**other.argument_spec)
        self.update(
            mutually_exclusive=other.mutually_exclusive,
            required_together=other.required_together,
            required_one_of=other.required_one_of,
            required_if=other.required_if,
            required_by=other.required_by,
        )
        return self

    def create_ansible_module_helper(
        self, clazz: type[_T], args: tuple, **kwargs: t.Any
    ) -> _T:
        for forbidden_name in (
            "argument_spec",
            "mutually_exclusive",
            "required_together",
            "required_one_of",
            "required_if",
            "required_by",
        ):
            if forbidden_name in kwargs:
                raise ValueError(
                    f"You must not provide a {forbidden_name} keyword parameter to create_ansible_module_helper()"
                )
        instance = clazz(  # type: ignore
            *args,
            argument_spec=self.argument_spec,
            mutually_exclusive=self.mutually_exclusive,
            required_together=self.required_together,
            required_one_of=self.required_one_of,
            required_if=self.required_if,
            required_by=self.required_by,
            **kwargs,
        )
        return instance

    def create_ansible_module(self, **kwargs: t.Any) -> AnsibleModule:
        return self.create_ansible_module_helper(AnsibleModule, (), **kwargs)


__all__ = ("ArgumentSpec",)
