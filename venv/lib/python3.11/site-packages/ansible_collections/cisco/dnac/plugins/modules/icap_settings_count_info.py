#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: icap_settings_count_info
short_description: Information module for Icap Settings
  Count
description:
  - Get all Icap Settings Count. - > Retrieves the count
    of deployed ICAP configurations while supporting
    basic filtering. For detailed information about
    the usage of the API, please refer to the Open API
    specification document - https //github.com/cisco-en-
    programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-ICAP_APIs-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  captureType:
    description:
      - CaptureType query parameter. Catalyst Center
        ICAP type.
    type: str
  captureStatus:
    description:
      - CaptureStatus query parameter. Catalyst Center
        ICAP status.
    type: str
  clientMac:
    description:
      - ClientMac query parameter. The client device
        MAC address in ICAP configuration.
    type: str
  apId:
    description:
      - ApId query parameter. The AP device's UUID.
    type: str
  wlcId:
    description:
      - WlcId query parameter. The wireless controller
        device's UUID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sensors
      RetrievesTheCountOfDeployedICAPConfigurationsWhileSupportingBasicFiltering
    description: Complete reference of the RetrievesTheCountOfDeployedICAPConfigurationsWhileSupportingBasicFiltering
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-count-of-deployed-icap-configurations-while-supporting-basic-filtering
notes:
  - SDK Method used are
    sensors.Sensors.retrieves_the_count_of_deployed_i_cap_configurations_while_supporting_basic_filtering,
  - Paths used are
    get /dna/intent/api/v1/icapSettings/count,
"""

EXAMPLES = r"""
---
- name: Get all Icap Settings Count
  cisco.dnac.icap_settings_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    captureType: string
    captureStatus: string
    clientMac: string
    apId: string
    wlcId: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": 0,
      "version": "string"
    }
"""
