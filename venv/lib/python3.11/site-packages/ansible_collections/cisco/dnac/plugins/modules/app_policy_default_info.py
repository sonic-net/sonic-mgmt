#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: app_policy_default_info
short_description: Information module for App Policy
  Default
description:
  - Get all App Policy Default.
  - Get default application policy.
version_added: '4.0.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy GetApplicationPolicyDefault
    description: Complete reference of the GetApplicationPolicyDefault
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-application-policy-default
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.get_application_policy_default,
  - Paths used are
    get /dna/intent/api/v1/app-policy-default,
"""

EXAMPLES = r"""
---
- name: Get all App Policy Default
  cisco.dnac.app_policy_default_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
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
          "instanceCreatedOn": 0,
          "instanceUpdatedOn": 0,
          "instanceVersion": 0,
          "createTime": 0,
          "deployed": true,
          "isSeeded": true,
          "isStale": true,
          "lastUpdateTime": 0,
          "name": "string",
          "namespace": "string",
          "provisioningState": "string",
          "qualifier": "string",
          "resourceVersion": 0,
          "targetIdList": [
            {}
          ],
          "type": "string",
          "cfsChangeInfo": [
            {}
          ],
          "customProvisions": [
            {}
          ],
          "deletePolicyStatus": "string",
          "internal": true,
          "isDeleted": true,
          "isEnabled": true,
          "isScopeStale": true,
          "iseReserved": true,
          "policyStatus": "string",
          "priority": 0,
          "pushed": true,
          "contractList": [
            {}
          ],
          "exclusiveContract": {
            "id": "string",
            "instanceId": 0,
            "displayName": "string",
            "instanceCreatedOn": 0,
            "instanceUpdatedOn": 0,
            "instanceVersion": 0,
            "clause": [
              {
                "id": "string",
                "instanceId": 0,
                "displayName": "string",
                "instanceCreatedOn": 0,
                "instanceUpdatedOn": 0,
                "instanceVersion": 0,
                "priority": 0,
                "type": "string",
                "relevanceLevel": "string"
              }
            ]
          },
          "identitySource": {
            "id": "string",
            "instanceId": 0,
            "displayName": "string",
            "instanceCreatedOn": 0,
            "instanceUpdatedOn": 0,
            "instanceVersion": 0,
            "state": "string",
            "type": "string"
          },
          "producer": {
            "id": "string",
            "instanceId": 0,
            "displayName": "string",
            "instanceCreatedOn": 0,
            "instanceUpdatedOn": 0,
            "instanceVersion": 0,
            "scalableGroup": [
              {
                "idRef": "string"
              }
            ]
          }
        }
      ],
      "version": "string"
    }
"""
