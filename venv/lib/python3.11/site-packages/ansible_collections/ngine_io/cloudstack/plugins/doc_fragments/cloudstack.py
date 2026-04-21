# -*- coding: utf-8 -*-

# Copyright (c) 2015, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):

    # Standard cloudstack documentation fragment
    DOCUMENTATION = r"""
options:
  api_key:
    description:
      - API key of the CloudStack API.
      - If not given, the C(CLOUDSTACK_KEY) env variable is considered.
    type: str
    required: true
  api_secret:
    description:
      - Secret key of the CloudStack API.
      - If not set, the C(CLOUDSTACK_SECRET) env variable is considered.
    type: str
    required: true
  api_url:
    description:
      - URL of the CloudStack API e.g. https://cloud.example.com/client/api.
      - If not given, the C(CLOUDSTACK_ENDPOINT) env variable is considered.
    type: str
    required: true
  api_http_method:
    description:
      - HTTP method used to query the API endpoint.
      - If not given, the C(CLOUDSTACK_METHOD) env variable is considered.
    type: str
    choices: [ get, post ]
    default: get
  api_timeout:
    description:
      - HTTP timeout in seconds.
      - If not given, the C(CLOUDSTACK_TIMEOUT) env variable is considered.
    type: int
    default: 10
  api_verify_ssl_cert:
    description:
      - Verify CA authority cert file.
      - If not given, the C(CLOUDSTACK_VERIFY) env variable is considered.
    type: str
  validate_certs:
    description:
      - If V(false), SSL certificates will not be validated.
      - If not given, the C(CLOUDSTACK_DANGEROUS_NO_TLS_VERIFY) env variable is considered.
      - This should only be used on personally controlled sites using self-signed certificates.
    type: bool
    default: true
    version_added: 2.4.0
requirements:
  - python >= 2.6
  - cs >= 0.9.0
notes:
  - A detailed guide about cloudstack modules can be found in the L(CloudStack Cloud Guide,../scenario_guides/guide_cloudstack.html).
  - This module supports check mode.
"""
