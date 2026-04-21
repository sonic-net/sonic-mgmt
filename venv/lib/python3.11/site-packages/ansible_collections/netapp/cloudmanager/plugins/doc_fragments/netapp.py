# -*- coding: utf-8 -*-

# Copyright: (c) 2021, NetApp Ansible Team <ng-ansibleteam@netapp.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type


class ModuleDocFragment(object):
    # Documentation fragment for CLOUDMANAGER
    CLOUDMANAGER = """
options:
  refresh_token:
    type: str
    description:
    - The refresh token for NetApp Cloud Manager API operations.

  sa_secret_key:
    type: str
    description:
    - The service account secret key for NetApp Cloud Manager API operations.

  sa_client_id:
    type: str
    description:
    - The service account secret client ID for NetApp Cloud Manager API operations.

  environment:
    type: str
    description:
    - The environment for NetApp Cloud Manager API operations.
    default: prod
    choices: ['prod', 'stage']
    version_added: 21.8.0

  feature_flags:
    description:
      - Enable or disable a new feature.
      - This can be used to enable an experimental feature or disable a new feature that breaks backward compatibility.
      - Supported keys and values are subject to change without notice.  Unknown keys are ignored.
    type: dict
    version_added: 21.11.0
notes:
  - The modules prefixed with na_cloudmanager are built to manage CloudManager and CVO deployments in AWS/GCP/Azure clouds.
  - If sa_client_id and sa_secret_key are provided, service account will be used in operations. refresh_token will be ignored.
"""
