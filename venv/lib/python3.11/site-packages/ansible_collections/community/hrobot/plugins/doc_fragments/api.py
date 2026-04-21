# -*- coding: utf-8 -*-

# Copyright (c) 2025 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    # Standard files documentation fragment
    DOCUMENTATION = r"""
options:
  hetzner_token:
    description:
      - The API token for the Robot web-service user.
    type: str
    required: true
  rate_limit_retry_timeout:
    description:
      - Timeout (in seconds) for waiting when rate limit exceeded errors are returned.
      - Set to V(0) to not retry.
      - Set to a negative value like V(-1) to retry forever.
    type: int
    default: -1
"""

    # Only for transition period
    _ROBOT_COMPAT_SHIM = r"""
options:
  hetzner_token:
    description:
      - The API token for the Robot web-service user.
      - One of O(hetzner_token) and O(hetzner_user) must be specified.
    required: false
  hetzner_user:
    description:
      - The username for the Robot web-service user.
      - One of O(hetzner_token) and O(hetzner_user) must be specified.
      - If O(hetzner_user) is specified, O(hetzner_password) must also be specified, and O(hetzner_token) must not be specified.
    required: false
  hetzner_password:
    description:
      - The password for the Robot web-service user.
      - If O(hetzner_password) is specified, O(hetzner_user) must also be specified, and O(hetzner_token) must not be specified.
    required: false
"""

    # Only for transition period
    _ROBOT_COMPAT_SHIM_DEPRECATION = r"""
options:
  hetzner_token:
    description:
      - The API token for the Robot web-service user.
      - One of O(hetzner_token) and O(hetzner_user) must be specified.
      - This option will be required from community.hrobot 3.0.0 on.
    required: false
  hetzner_user:
    description:
      - The username for the Robot web-service user.
      - One of O(hetzner_token) and O(hetzner_user) must be specified.
      - If O(hetzner_user) is specified, O(hetzner_password) must also be specified, and O(hetzner_token) must not be specified.
      - This option is deprecated for this module, and support will be removed in community.hrobot 3.0.0.
    required: false
  hetzner_password:
    description:
      - The password for the Robot web-service user.
      - If O(hetzner_password) is specified, O(hetzner_user) must also be specified, and O(hetzner_token) must not be specified.
      - This option is deprecated for this module, and support will be removed in community.hrobot 3.0.0.
    required: false
"""
