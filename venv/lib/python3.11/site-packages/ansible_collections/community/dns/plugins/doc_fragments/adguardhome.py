# -*- coding: utf-8 -*-

# Copyright (c) 2025 Markus Bergholz
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


class ModuleDocFragment(object):

    CONNECTIVITY = r"""
options:
  username:
    description:
      - AdGuardHome user.
    required: true
    type: str
  password:
    description:
      - Related password for the AdGuardHome user.
    required: true
    type: str
  host:
    description:
      - URL of AdGuardHome host.
      - For example, V(https://my-adguard.my-domain) or V(http://192.168.1.2).
    required: true
    type: str
  validate_certs:
    description:
      - Ability to disable TLS certificate validation.
      - >
        This should only set to V(false) when the network path between the host the module is run on and
        the AdGuard host is fully under your control and trusted.
    required: false
    type: bool
    default: true
"""
