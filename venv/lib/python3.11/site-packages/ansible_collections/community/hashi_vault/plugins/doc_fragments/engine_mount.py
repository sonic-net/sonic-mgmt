# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
options:
  engine_mount_point:
    description: The path where the secret backend is mounted.
    type: str
'''

    PLUGINS = r'''
options:
  engine_mount_point:
    vars:
      - name: ansible_hashi_vault_engine_mount_point
'''
