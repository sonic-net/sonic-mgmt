# -*- coding: utf-8 -*-
# Copyright (c) 2019, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = '''
options:
  api_url:
    description:
      - cloudscale.ch API URL.
      - This can also be passed in the C(CLOUDSCALE_API_URL) environment variable.
    default: https://api.cloudscale.ch/v1
    type: str
    version_added: 1.3.0
  api_token:
    description:
      - cloudscale.ch API token.
      - This can also be passed in the C(CLOUDSCALE_API_TOKEN) environment variable.
    required: true
    type: str
  api_timeout:
    description:
      - Timeout in seconds for calls to the cloudscale.ch API.
      - This can also be passed in the C(CLOUDSCALE_API_TIMEOUT) environment variable.
    default: 45
    type: int
notes:
  - All operations are performed using the cloudscale.ch public API v1.
  - "For details consult the full API documentation: U(https://www.cloudscale.ch/en/api/v1)."
  - A valid API token is required for all operations. You can create as many tokens as you like using the cloudscale.ch control panel at
    U(https://control.cloudscale.ch).
'''
