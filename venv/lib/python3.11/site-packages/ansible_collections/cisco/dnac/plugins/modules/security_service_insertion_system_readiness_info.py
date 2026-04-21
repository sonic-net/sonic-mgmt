#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_service_insertion_system_readiness_info
short_description: Information module for Security Service
  Insertion System Readiness
description:
  - Get all Security Service Insertion System Readiness.
    - > Retrieves readiness information for Security
    Service Insertion, including integration status,
    security group details, and access control information.
version_added: '6.18.0'
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
  - name: Cisco DNA Center documentation for SDA SecurityServiceInsertionReadiness
    description: Complete reference of the SecurityServiceInsertionReadiness
      API.
    link: https://developer.cisco.com/docs/dna-center/#!security-service-insertion-readiness
notes:
  - SDK Method used are
    sda.Sda.security_service_insertion_readiness,
  - Paths used are
    get /dna/intent/api/v1/securityServiceInsertion/systemReadiness,
"""

EXAMPLES = r"""
---
- name: Get all Security Service Insertion System Readiness
  cisco.dnac.security_service_insertion_system_readiness_info:
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
      "response": {
        "readiness": "string",
        "ise": {
          "integrationStatus": "string",
          "version": "string",
          "syncStatus": "string",
          "readiness": "string"
        },
        "securityGroup": {
          "securityGroupsCount": 0,
          "sgtManagedBy": "string",
          "readiness": "string"
        },
        "accessControlDetails": {
          "accessControlAppPkgStatus": "string",
          "fabricSitesCount": 0,
          "readiness": "string"
        }
      },
      "version": "string"
    }
"""
