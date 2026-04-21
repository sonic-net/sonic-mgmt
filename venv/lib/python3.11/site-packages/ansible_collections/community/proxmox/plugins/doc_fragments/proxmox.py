# -*- coding: utf-8 -*-
# Copyright (c) Ansible project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):
    # Common parameters for Proxmox VE modules
    DOCUMENTATION = r"""
options:
  api_host:
    description:
      - Specify the target host of the Proxmox VE cluster.
      - Uses the E(PROXMOX_HOST) environment variable if not specified.
    type: str
    required: true
  api_port:
    description:
      - Specify the target port of the Proxmox VE cluster.
      - Uses the E(PROXMOX_PORT) environment variable if not specified.
    type: int
    required: false
  api_user:
    description:
      - Specify the user to authenticate with.
      - Uses the E(PROXMOX_USER) environment variable if not specified.
    type: str
    required: true
  api_password:
    description:
      - Specify the password to authenticate with.
      - Uses the E(PROXMOX_PASSWORD) environment variable if not specified.
    type: str
  api_token_id:
    description:
      - Specify the token ID.
      - Uses the E(PROXMOX_TOKEN_ID) environment variable if not specified.
    type: str
  api_token_secret:
    description:
      - Specify the token secret.
      - Uses the E(PROXMOX_TOKEN_SECRET) environment variable if not specified.
    type: str
  validate_certs:
    description:
      - If V(false), SSL certificates will not be validated.
      - This should only be used on personally controlled sites using self-signed certificates.
      - Uses the E(PROXMOX_VALIDATE_CERTS) environment variable if not specified.
    type: bool
    default: false
requirements: ["proxmoxer >= 2.0", "requests"]
"""

    SELECTION = r"""
options:
  vmid:
    description:
      - Specifies the instance ID.
      - If not set the next available ID will be fetched from ProxmoxAPI.
    type: int
  node:
    description:
      - Proxmox VE node on which to operate.
      - Only required for O(state=present).
      - For every other states it will be autodiscovered.
    type: str
  pool:
    description:
      - Add the new VM to the specified pool.
    type: str
"""

    ACTIONGROUP_PROXMOX = r"""
options: {}
attributes:
  action_group:
    description: Use C(group/community.proxmox.proxmox) in C(module_defaults) to set defaults for this module.
    support: full
    membership:
      - community.proxmox.proxmox
"""
