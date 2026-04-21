# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this doc fragment is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations


class ModuleDocFragment:
    DOCUMENTATION = r"""
options:
  name_encoding:
    description:
      - How to encode names (DNS names, URIs, email addresses) in return values.
      - V(ignore) will use the encoding returned by the backend.
      - V(idna) will convert all labels of domain names to IDNA encoding. IDNA2008 will be preferred, and IDNA2003 will be
        used if IDNA2008 encoding fails.
      - V(unicode) will convert all labels of domain names to Unicode. IDNA2008 will be preferred, and IDNA2003 will be used
        if IDNA2008 decoding fails.
      - B(Note) that V(idna) and V(unicode) require the L(idna Python library,https://pypi.org/project/idna/) to be installed.
    type: str
    default: ignore
    choices:
      - ignore
      - idna
      - unicode
requirements:
  - If O(name_encoding) is set to another value than V(ignore), the L(idna Python library,https://pypi.org/project/idna/)
    needs to be installed.
"""
