#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: field_notices_results_network_devices_network_device_id_notices_info
short_description: Information module for Field Notices
  Results Network Devices Network Device Id Notices
description:
  - Get all Field Notices Results Network Devices Network
    Device Id Notices.
  - Get field notices affecting the network device.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  networkDeviceId:
    description:
      - NetworkDeviceId path parameter. Id of the network
        device.
    type: str
  id:
    description:
      - Id query parameter. Id of the field notice.
    type: str
  type:
    description:
      - Type query parameter. Return field notices with
        this type. Available values SOFTWARE, HARDWARE.
    type: str
  offset:
    description:
      - >
        Offset query parameter. The first record to
        show for this page; the first record is numbered
        1. Default value is 1.
    type: int
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. Minimum value is 1. Maximum
        value is 500. Default value is 500.
    type: int
  sortBy:
    description:
      - SortBy query parameter. A property within the
        response to sort by.
    type: str
  order:
    description:
      - >
        Order query parameter. Whether ascending or
        descending order should be used to sort the
        response. Available values asc, desc. Default
        value is asc.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Compliance
      GetFieldNoticesAffectingTheNetworkDevice
    description: Complete reference of the GetFieldNoticesAffectingTheNetworkDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-field-notices-affecting-the-network-device
notes:
  - SDK Method used are
    compliance.Compliance.get_field_notices_affecting_the_network_device,
  - Paths used are
    get /dna/intent/api/v1/fieldNotices/results/networkDevices/{networkDeviceId}/notices,
"""

EXAMPLES = r"""
---
- name: Get all Field Notices Results Network Devices
    Network Device Id Notices
  cisco.dnac.field_notices_results_network_devices_network_device_id_notices_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
    type: string
    offset: 0
    limit: 0
    sortBy: string
    order: string
    networkDeviceId: string
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
          "name": "string",
          "publicationUrl": 0,
          "deviceCount": 0,
          "potentialDeviceCount": 0,
          "type": "string",
          "firstPublishDate": 0,
          "lastUpdatedDate": 0,
          "matchConfidence": "string",
          "matchReason": "string",
          "networkDeviceId": "string"
        }
      ],
      "version": "string"
    }
"""
