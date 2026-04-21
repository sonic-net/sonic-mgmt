# -*- coding: utf-8 -*-

# Copyright (c) 2021 René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = """
options:
  api_key:
    description:
      - API key of the Vultr API.
      - Fallback environment variable C(VULTR_API_KEY).
    type: str
    required: true
  api_timeout:
    description:
      - HTTP timeout to Vultr API.
      - Fallback environment variable C(VULTR_API_TIMEOUT).
    type: int
    default: 180
  api_retries:
    description:
      - Amount of retries in case of the Vultr API retuns an HTTP error code, such as
          - 429 Too Many Requests
          - 500 Internal Server Error
          - 504 Gateway Time-out
      - Fallback environment variable C(VULTR_API_RETRIES).
    type: int
    default: 5
  api_retry_max_delay:
    description:
      - Retry backoff delay in seconds is exponential up to this max. value, in seconds.
      - Fallback environment variable C(VULTR_API_RETRY_MAX_DELAY).
    type: int
    default: 12
  api_endpoint:
    description:
      - URL to API endpint (without trailing slash).
      - Fallback environment variable C(VULTR_API_ENDPOINT).
    type: str
    default: https://api.vultr.com/v2
  validate_certs:
    description:
      - Validate SSL certs of the Vultr API.
    type: bool
    default: true
notes:
  - Also see the API documentation on U(https://www.vultr.com/api/).
"""
