#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: compliance_device_by_id_info
short_description: Information module for Compliance
  Device By Id
description:
  - Get all Compliance Device By Id.
  - Return compliance detailed report for a device.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceUuid:
    description:
      - DeviceUuid path parameter. Device Id.
    type: str
  category:
    description:
      - >
        Category query parameter. Category can have
        any value among 'INTENT', 'RUNNING_CONFIG' ,
        'IMAGE' , 'PSIRT' , 'DESIGN_OOD' , 'EOX' , 'NETWORK_SETTINGS'.
    type: str
  complianceType:
    description:
      - >
        ComplianceType query parameter. Specify "Compliance
        type(s)" separated by commas. The Compliance
        type can be 'APPLICATION_VISIBILITY', 'EOX',
        'FABRIC', 'IMAGE', 'NETWORK_PROFILE', 'NETWORK_SETTINGS',
        'PSIRT', 'RUNNING_CONFIG', 'WORKFLOW'.
    type: str
  diffList:
    description:
      - DiffList query parameter. Diff list pass true
        to fetch the diff list.
    type: bool
  status:
    description:
      - >
        Status query parameter. 'COMPLIANT', 'NON_COMPLIANT',
        'ERROR', 'IN_PROGRESS', 'NOT_APPLICABLE', 'NOT_AVAILABLE',
        'WARNING', 'REMEDIATION_IN_PROGRESS' can be
        the value of the compliance 'status' parameter.
        COMPLIANT Device currently meets the compliance
        requirements. NON_COMPLIANT One of the compliance
        requirements like Software Image, PSIRT, Network
        Profile, Startup vs Running, etc. Are not met.
        ERROR Compliance is unable to compute status
        due to underlying errors. IN_PROGRESS Compliance
        check is in progress for the device. NOT_APPLICABLE
        Device is not supported for compliance, or minimum
        license requirement is not met. NOT_AVAILABLE
        Compliance is not available for the device.
        COMPLIANT_WARNING The device is compliant with
        warning if the last date of support is nearing.
        REMEDIATION_IN_PROGRESS Compliance remediation
        is in progress for the device.
    type: str
  remediationSupported:
    description:
      - >
        RemediationSupported query parameter. The 'remediationSupported'
        parameter can be set to 'true' or 'false'. The
        result will be a combination of both values
        if it is not provided.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Compliance
      ComplianceDetailsOfDevice
    description: Complete reference of the ComplianceDetailsOfDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!compliance-details-of-device
notes:
  - SDK Method used are
    compliance.Compliance.compliance_details_of_device,
  - Paths used are
    get /dna/intent/api/v1/compliance/{deviceUuid}/detail,
"""

EXAMPLES = r"""
---
- name: Get all Compliance Device By Id
  cisco.dnac.compliance_device_by_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    category: string
    complianceType: string
    diffList: true
    status: string
    remediationSupported: true
    deviceUuid: string
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
          "deviceUuid": "string",
          "complianceType": "string",
          "status": "string",
          "state": "string",
          "lastSyncTime": 0,
          "lastUpdateTime": 0,
          "sourceInfoList": [
            {
              "name": "string",
              "nameWithBusinessKey": "string",
              "sourceEnum": "string",
              "type": "string",
              "appName": "string",
              "count": 0,
              "ackStatus": "string",
              "businessKey": {
                "resourceName": "string",
                "businessKeyAttributes": {},
                "otherAttributes": {
                  "name": "string",
                  "cfsAttributes": {
                    "displayName": "string",
                    "appName": "string",
                    "description": "string",
                    "source": "string",
                    "type": "string"
                  }
                }
              },
              "diffList": [
                {
                  "op": "string",
                  "configuredValue": "string",
                  "intendedValue": "string",
                  "moveFromPath": "string",
                  "businessKey": "string",
                  "path": "string",
                  "extendedAttributes": {
                    "attributeDisplayName": "string",
                    "path": "string",
                    "dataConverter": "string",
                    "type": "string"
                  },
                  "ackStatus": "string",
                  "instanceUUID": "string",
                  "displayName": "string"
                }
              ],
              "displayName": "string"
            }
          ],
          "ackStatus": "string",
          "version": "string",
          "remediationSupported": true
        }
      ],
      "deviceUuid": "string"
    }
"""
