# -*- coding: utf-8 -*-

# Copyright (c) 2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import os.path
import re
import typing as t

from ansible_collections.community.dns.plugins.module_utils.names import (
    InvalidDomainName,
    normalize_label,
    split_into_labels,
)


_BEGIN_SUBSET_MATCHER = re.compile(r"===BEGIN ([^=]*) DOMAINS===")
_END_SUBSET_MATCHER = re.compile(r"===END ([^=]*) DOMAINS===")


class PublicSuffixEntry:
    """
    Contains a Public Suffix List entry with metadata.
    """

    def __init__(
        self,
        labels: tuple[str, ...],
        exception_rule: bool = False,
        part: str | None = None,
    ) -> None:
        self.labels = labels
        self.exception_rule = exception_rule
        self.part = part

    def matches(self, normalized_labels) -> bool:
        """
        Match PSL entry with a given normalized list of labels.
        """
        if len(normalized_labels) < len(self.labels):
            return False
        for i, label in enumerate(self.labels):
            normalized_label = normalized_labels[i]
            if label not in (normalized_label, "*"):
                return False
        return True


def select_prevailing_rule(rules: list[PublicSuffixEntry]) -> PublicSuffixEntry:
    """
    Given a non-empty set of rules matching a domain name, finds the prevailing rule.

    It uses the algorithm specified on https://publicsuffix.org/list/.
    """
    max_length_rule = rules[0]
    max_length = len(max_length_rule.labels)
    for rule in rules:
        if rule.exception_rule:
            return rule
        if len(rule.labels) > max_length:
            max_length = len(rule.labels)
            max_length_rule = rule
    return max_length_rule


class PublicSuffixList:
    """
    Contains the Public Suffix List.
    """

    def __init__(self, rules: t.List[PublicSuffixEntry]) -> None:
        self._generic_rule = PublicSuffixEntry(("*",))
        self._rules = sorted(rules, key=lambda entry: entry.labels)

    @classmethod
    def load(cls, filename: str) -> t.Self:
        """
        Load Public Suffix List from the given filename.
        """
        rules: list[PublicSuffixEntry] = []
        part: str | None = None
        with open(filename, "rb") as content_file:
            content = content_file.read().decode("utf-8")
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("//") or not line:
                m = _BEGIN_SUBSET_MATCHER.search(line)
                if m:
                    part = m.group(1).lower()
                m = _END_SUBSET_MATCHER.search(line)
                if m:
                    part = None
                continue
            if part is None:
                raise AssertionError("Internal error: found PSL entry with no part!")
            exception_rule = False
            if line.startswith("!"):
                exception_rule = True
                line = line[1:]
            if line.startswith("."):
                line = line[1:]
            labels = tuple(
                normalize_label(label) for label in split_into_labels(line)[0]
            )
            rules.append(
                PublicSuffixEntry(labels, exception_rule=exception_rule, part=part)
            )
        return cls(rules)

    def get_suffix_length_and_rule(
        self, normalized_labels: list[str], icann_only: bool = False
    ) -> tuple[int, PublicSuffixEntry | None]:
        """
        Given a list of normalized labels, searches for a matching rule.

        Returns the tuple ``(suffix_length, rule)``. The ``rule`` is never ``None``
        except if ``normalized_labels`` is empty, in which case ``(0, None)`` is returned.

        If ``icann_only`` is set to ``True``, only official ICANN rules are used. If
        ``icann_only`` is ``False`` (default), also private rules are used.
        """
        if not normalized_labels:
            return 0, None

        # Find matching rules
        rules: list[PublicSuffixEntry] = []
        for rule in self._rules:
            if icann_only and rule.part != "icann":
                continue
            if rule.matches(normalized_labels):
                rules.append(rule)
        if not rules:
            rules.append(self._generic_rule)

        # Select prevailing rule
        rule = select_prevailing_rule(rules)

        # Determine suffix
        suffix_length = len(rule.labels)
        if rule.exception_rule:
            suffix_length -= 1

        # Return result
        return suffix_length, rule

    def get_suffix(
        self,
        domain: str,
        keep_unknown_suffix: bool = True,
        normalize_result: bool = False,
        icann_only: bool = False,
    ) -> str:
        """
        Given a domain name, extracts the public suffix.

        If ``keep_unknown_suffix`` is set to ``False``, only suffixes matching explicit
        entries from the PSL are returned. If ``keep_unknown_suffix`` is ``True`` (default),
        the implicit ``*`` rule is used if no other rule matches.

        If ``normalize_result`` is set to ``True``, the result is re-combined form the
        normalized labels. In that case, the result is lower-case ASCII. If
        ``normalize_result`` is ``False`` (default), the result ``result`` always satisfies
        ``domain.endswith(result)``.

        If ``icann_only`` is set to ``True``, only official ICANN rules are used. If
        ``icann_only`` is ``False`` (default), also private rules are used.
        """
        # Split into labels and normalize
        try:
            labels, tail = split_into_labels(domain)
            normalized_labels = [normalize_label(label) for label in labels]
        except InvalidDomainName:
            return ""
        if normalize_result:
            labels = normalized_labels

        # Get suffix length
        suffix_length, rule = self.get_suffix_length_and_rule(
            normalized_labels, icann_only=icann_only
        )
        if rule is None:
            return ""
        if not keep_unknown_suffix and rule is self._generic_rule:
            return ""
        return ".".join(reversed(labels[:suffix_length])) + tail

    def get_registrable_domain(
        self,
        domain: str,
        keep_unknown_suffix: bool = True,
        only_if_registerable: bool = True,
        normalize_result: bool = False,
        icann_only: bool = False,
    ) -> str:
        """
        Given a domain name, extracts the registrable domain. This is the public suffix
        including the last label before the suffix.

        If ``keep_unknown_suffix`` is set to ``False``, only suffixes matching explicit
        entries from the PSL are returned. If no suffix can be found, ``''`` is returned.
        If ``keep_unknown_suffix`` is ``True`` (default), the implicit ``*`` rule is used
        if no other rule matches.

        If ``only_if_registerable`` is set to ``False``, the public suffix is returned
        if there is no label before the suffix. If ``only_if_registerable`` is ``True``
        (default), ``''`` is returned in that case.

        If ``normalize_result`` is set to ``True``, the result is re-combined form the
        normalized labels. In that case, the result is lower-case ASCII. If
        ``normalize_result`` is ``False`` (default), the result ``result`` always satisfies
        ``domain.endswith(result)``.

        If ``icann_only`` is set to ``True``, only official ICANN rules are used. If
        ``icann_only`` is ``False`` (default), also private rules are used.
        """
        # Split into labels and normalize
        try:
            labels, tail = split_into_labels(domain)
            normalized_labels = [normalize_label(label) for label in labels]
        except InvalidDomainName:
            return ""
        if normalize_result:
            labels = normalized_labels

        # Get suffix length
        suffix_length, rule = self.get_suffix_length_and_rule(
            normalized_labels, icann_only=icann_only
        )
        if rule is None:
            return ""
        if not keep_unknown_suffix and rule is self._generic_rule:
            return ""
        if suffix_length < len(labels):
            suffix_length += 1
        elif only_if_registerable:
            return ""
        return ".".join(reversed(labels[:suffix_length])) + tail


# The official Public Suffix List
PUBLIC_SUFFIX_LIST = PublicSuffixList.load(
    os.path.join(os.path.dirname(__file__), "..", "public_suffix_list.dat")
)
