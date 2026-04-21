# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this doc fragment is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations


class ModuleDocFragment:
    # Standard documentation fragment
    DOCUMENTATION = r"""
options: {}
attributes:
  check_mode:
    description: Can run in C(check_mode) and return changed status prediction without modifying target.
  diff_mode:
    description: Will return details on what has changed (or possibly needs changing in C(check_mode)), when in diff mode.
  idempotent:
    description:
      - When run twice in a row outside check mode, with the same arguments, the second invocation indicates no change.
      - This assumes that the system controlled/queried by the module has not changed in a relevant way.
"""

    # Should be used together with the standard fragment
    IDEMPOTENT_NOT_MODIFY_STATE = r"""
options: {}
attributes:
  idempotent:
    support: full
    details:
      - This action does not modify state.
"""

    # Should be used together with the standard fragment
    INFO_MODULE = r"""
options: {}
attributes:
  check_mode:
    support: full
    details:
      - This action does not modify state.
  diff_mode:
    support: N/A
    details:
      - This action does not modify state.
"""

    ACTIONGROUP_ACME = r"""
options: {}
attributes:
  action_group:
    description: Use C(group/acme) or C(group/community.crypto.acme) in C(module_defaults) to set defaults for this module.
    support: full
    membership:
      - community.crypto.acme
      - acme
"""

    FACTS = r"""
options: {}
attributes:
  facts:
    description: Action returns an C(ansible_facts) dictionary that will update existing host facts.
"""

    # Should be used together with the standard fragment and the FACTS fragment
    FACTS_MODULE = r"""
options: {}
attributes:
  check_mode:
    support: full
    details:
      - This action does not modify state.
  diff_mode:
    support: N/A
    details:
      - This action does not modify state.
  facts:
    support: full
"""

    FILES = r"""
options: {}
attributes:
  safe_file_operations:
    description: Uses Ansible's strict file operation functions to ensure proper permissions and avoid data corruption.
"""

    FLOW = r"""
options: {}
attributes:
  action:
    description: Indicates this has a corresponding action plugin so some parts of the options can be executed on the controller.
  async:
    description: Supports being used with the C(async) keyword.
"""
