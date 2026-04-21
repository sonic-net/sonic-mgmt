#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: endpoint_analytics_endpoints_anc_policy_delete
short_description: Resource module for Endpoint Analytics
  Endpoints Anc-Policy Delete
description:
  - Manage operation delete of the resource Endpoint
    Analytics Endpoints Anc-Policy Delete.
  - Revokes given ANC policy from the endpoint.
version_added: '6.16.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  epId:
    description: EpId path parameter. Unique identifier
      for the endpoint.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for AI Endpoint
      Analytics RevokeANCPolicy
    description: Complete reference of the RevokeANCPolicy
      API.
    link: https://developer.cisco.com/docs/dna-center/#!revoke-anc-policy
notes:
  - SDK Method used are
    ai_endpoint_analytics.AiEndpointAnalytics.revoke_anc_policy,
  - Paths used are
    delete /dna/intent/api/v1/endpoint-analytics/endpoints/{epId}/anc-policy,
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.endpoint_analytics_endpoints_anc-policy_delete:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    epId: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
