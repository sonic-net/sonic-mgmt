# -*- coding: utf-8 -*-

# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


class ModuleDocFragment(object):

    # Docker doc fragment
    DOCUMENTATION = r"""
---
options:
  filters:
    description:
      - A list of include/exclude filters that allows to select/deselect hosts for this inventory.
      - Filters are processed sequentially until the first filter where O(filters[].exclude) or O(filters[].include) matches
        is found. In case O(filters[].exclude) matches, the host is excluded, and in case O(filters[].include) matches, the
        host is included. In case no filter matches, the host is included.
    type: list
    elements: dict
    suboptions:
      exclude:
        description:
          - A Jinja2 condition. If it matches for a host, that host is B(excluded).
          - Exactly one of O(filters[].exclude) and O(filters[].include) can be specified.
        type: str
      include:
        description:
          - A Jinja2 condition. If it matches for a host, that host is B(included).
          - Exactly one of O(filters[].exclude) and O(filters[].include) can be specified.
        type: str
"""
