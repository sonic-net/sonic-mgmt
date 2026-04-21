# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
options:
  wrap_ttl:
    description: Specifies response wrapping token creation with duration. For example C(15s), C(20m), C(25h).
    type: str
'''

    PLUGINS = r'''
options:
  wrap_ttl:
    vars:
      - name: ansible_hashi_vault_wrap_ttl
'''
