# Copyright (c) 2025 Ansible project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this doc fragment is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations


class ModuleDocFragment:
    """
    Doc fragments for cryptography requirements.

    Must be kept in sync with plugins/module_utils/_cryptography_dep.py.
    """

    # Corresponds to the plugins.module_utils._cryptography_dep.COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION constant
    MINIMUM = r"""
requirements:
  - cryptography >= 3.3
options: {}
"""
