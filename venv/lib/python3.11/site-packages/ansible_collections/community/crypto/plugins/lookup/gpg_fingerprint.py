# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
name: gpg_fingerprint
short_description: Retrieve a GPG fingerprint from a GPG public or private key file
author: Felix Fontein (@felixfontein)
version_added: 2.15.0
description:
  - Takes a list of filenames pointing to GPG public or private key files. Returns the fingerprints for each of these keys.
options:
  _terms:
    description:
      - A path to a GPG public or private key.
    type: list
    elements: path
    required: true
requirements:
  - GnuPG (C(gpg) executable)
seealso:
  - plugin: community.crypto.gpg_fingerprint
    plugin_type: filter
"""

EXAMPLES = r"""
---
- name: Show fingerprint of GPG public key
  ansible.builtin.debug:
    msg: "{{ lookup('community.crypto.gpg_fingerprint', '/path/to/public_key.gpg') }}"
"""

RETURN = r"""
_value:
  description:
    - The fingerprints of the provided public or private GPG keys.
    - The list has one entry for every path provided.
  type: list
  elements: string
"""

import os
import typing as t

from ansible.errors import AnsibleLookupError
from ansible.module_utils.common.text.converters import to_text
from ansible.plugins.lookup import LookupBase

from ansible_collections.community.crypto.plugins.module_utils._gnupg.cli import (
    GPGError,
    get_fingerprint_from_file,
)
from ansible_collections.community.crypto.plugins.plugin_utils._gnupg import (
    PluginGPGRunner,
)


class LookupModule(LookupBase):
    def run(
        self, terms: list[t.Any], variables: None = None, **kwargs: t.Any
    ) -> list[str]:
        self.set_options(direct=kwargs)
        if self._loader is None:
            raise AssertionError(
                "Contract violation: self._loader is None"
            )  # pragma: no cover

        try:
            gpg = PluginGPGRunner(cwd=self._loader.get_basedir())
            result = []
            for i, path in enumerate(terms):
                if not isinstance(path, (str, bytes, os.PathLike)):
                    raise AnsibleLookupError(
                        f"Lookup parameter #{i} should be string or a path object, but got {type(path)}"
                    )
                result.append(
                    get_fingerprint_from_file(gpg_runner=gpg, path=to_text(path))
                )
            return result
        except GPGError as exc:
            raise AnsibleLookupError(str(exc)) from exc
