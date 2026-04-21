#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_image_updates_count_info
short_description: Information module for Network Device
  Image Updates Count
description:
  - Get all Network Device Image Updates Count.
  - Returns the count of network device image updates
    based on the given filter criteria.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id query parameter. Update id which is unique
        for each network device under the parentId.
    type: str
  parentId:
    description:
      - ParentId query parameter. Updates that have
        this parent id.
    type: str
  networkDeviceId:
    description:
      - NetworkDeviceId query parameter. Network device
        id.
    type: str
  status:
    description:
      - Status query parameter. Status of the image
        update. Available values FAILURE, SUCCESS, IN_PROGRESS,
        PENDING.
    type: str
  imageName:
    description:
      - ImageName query parameter. Software image name
        for the update.
    type: str
  hostName:
    description:
      - >
        HostName query parameter. Host name of the network
        device for the image update. Supports case-
        insensitive partial search.
    type: str
  managementAddress:
    description:
      - ManagementAddress query parameter. Management
        address of the network device.
    type: str
  startTime:
    description:
      - StartTime query parameter. Image update started
        after the given time (as milliseconds since
        UNIX epoch).
    type: float
  endTime:
    description:
      - EndTime query parameter. Image update started
        before the given time (as milliseconds since
        UNIX epoch).
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) CountOfNetworkDeviceImageUpdates
    description: Complete reference of the CountOfNetworkDeviceImageUpdates
      API.
    link: https://developer.cisco.com/docs/dna-center/#!count-of-network-device-image-updates
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.count_of_network_device_image_updates,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceImageUpdates/count,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Image Updates Count
  cisco.dnac.network_device_image_updates_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
    parentId: string
    networkDeviceId: string
    status: string
    imageName: string
    hostName: string
    managementAddress: string
    startTime: 0
    endTime: 0
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
        "count": 0
      },
      "version": "string"
    }
"""
