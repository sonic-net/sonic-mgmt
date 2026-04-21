#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: applications_v2_info
short_description: Information module for Applications
  V2
description:
  - Get all Applications V2.
  - Get application/s by offset/limit or by name.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  attributes:
    description:
      - Attributes query parameter. Attributes to retrieve,
        valid value application.
    type: str
  name:
    description:
      - Name query parameter. The application name.
    type: str
  offset:
    description:
      - Offset query parameter. The starting point or
        index from where the paginated results should
        begin.
    type: int
  limit:
    description:
      - >
        Limit query parameter. The limit which is the
        maximum number of items to include in a single
        page of results, max value 500.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy GetApplicationsV2
    description: Complete reference of the GetApplicationsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-applications-v-2
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.get_applications_v2,
  - Paths used are
    get /dna/intent/api/v2/applications,
"""

EXAMPLES = r"""
---
- name: Get all Applications V2
  cisco.dnac.applications_v2_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    attributes: string
    name: string
    offset: 0
    limit: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "id": "string",
          "instanceId": 0,
          "displayName": "string",
          "instanceVersion": 0,
          "identitySource": {
            "id": "string",
            "type": "string"
          },
          "indicativeNetworkIdentity": [
            {
              "id": "string",
              "displayName": "string",
              "lowerPort": 0,
              "ports": "string",
              "protocol": "string",
              "upperPort": 0
            }
          ],
          "name": "string",
          "namespace": "string",
          "networkApplications": [
            {
              "id": "string",
              "appProtocol": "string",
              "applicationSubType": "string",
              "applicationType": "string",
              "categoryId": "string",
              "displayName": "string",
              "dscp": "string",
              "engineId": "string",
              "helpString": "string",
              "longDescription": "string",
              "name": "string",
              "popularity": 0,
              "rank": 0,
              "selectorId": "string",
              "serverName": "string",
              "url": "string",
              "trafficClass": "string"
            }
          ],
          "networkIdentity": [
            {
              "id": "string",
              "displayName": "string",
              "ipv4Subnet": [
                "string"
              ],
              "ipv6Subnet": [
                {}
              ],
              "lowerPort": 0,
              "ports": "string",
              "protocol": "string",
              "upperPort": 0
            }
          ],
          "parentScalableGroup": {
            "id": "string",
            "idRef": "string"
          },
          "qualifier": "string",
          "scalableGroupExternalHandle": "string",
          "scalableGroupType": "string",
          "type": "string"
        }
      ],
      "version": "string"
    }
"""
