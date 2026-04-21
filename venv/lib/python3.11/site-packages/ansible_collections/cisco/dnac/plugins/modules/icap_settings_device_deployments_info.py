#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: icap_settings_device_deployments_info
short_description: Information module for Icap Settings
  Device Deployments
description:
  - Get all Icap Settings Device Deployments. - > Retrieves
    ICAP configuration deployment statuss per device
    based on filter criteria. For detailed information
    about the usage of the API, please refer to the
    Open API specification document - https //github.com/cisco-en-
    programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-ICAP_APIs-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deployActivityId:
    description:
      - DeployActivityId query parameter. Activity from
        the /deploy task response.
    type: str
  networkDeviceIds:
    description:
      - NetworkDeviceIds query parameter. Device ids,
        retrievable from the id attribute in intent/api/v1/network-device.
    type: str
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: int
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page.
    type: int
  sortBy:
    description:
      - SortBy query parameter. A property within the
        response to sort by.
    type: str
  order:
    description:
      - Order query parameter. Whether ascending or
        descending order should be used to sort the
        response.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sensors
      GetDeviceDeploymentStatus
    description: Complete reference of the GetDeviceDeploymentStatus
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-device-deployment-status
notes:
  - SDK Method used are
    sensors.Sensors.get_device_deployment_status,
  - Paths used are
    get /dna/intent/api/v1/icapSettings/deviceDeployments,
"""

EXAMPLES = r"""
---
- name: Get all Icap Settings Device Deployments
  cisco.dnac.icap_settings_device_deployments_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deployActivityId: string
    networkDeviceIds: string
    offset: 0
    limit: 0
    sortBy: string
    order: string
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
          "deployActivityId": "string",
          "networkDeviceId": "string",
          "configGroupName": "string",
          "configGroupVersion": 0,
          "status": "string",
          "startTime": 0,
          "endTime": 0,
          "error": {}
        }
      ],
      "version": "string"
    }
"""
