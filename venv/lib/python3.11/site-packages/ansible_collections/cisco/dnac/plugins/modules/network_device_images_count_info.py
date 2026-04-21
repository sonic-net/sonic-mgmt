#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_images_count_info
short_description: Information module for Network Device
  Images Count
description:
  - Get all Network Device Images Count.
  - Returns the count of network devices based on the
    given filters.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  managementAddress:
    description:
      - ManagementAddress query parameter. IP address
        or DNS name used to access and manage network
        devices.
    type: str
  networkDeviceImageStatus:
    description:
      - >
        NetworkDeviceImageStatus query parameter. Network
        device image status with respect to golden images.
        Available values OUTDATED, UP_TO_DATE, UNKNOWN,
        CONFLICTED, UNSUPPORTED.
    type: str
  networkDeviceUpdateStatus:
    description:
      - >
        NetworkDeviceUpdateStatus query parameter. Network
        device current update status with respect to
        golden images. Available values DISTRIBUTION_PENDING,
        DISTRIBUTION_IN_PROGRESS, DISTRIBUTION_FAILED,
        ACTIVATION_PENDING, ACTIVATION_IN_PROGRESS,
        ACTIVATION_FAILED, DEVICE_UP_TO_DATE,UNKNOWN.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) CountOfNetworkDevicesForTheGivenStatusFilters
    description: Complete reference of the CountOfNetworkDevicesForTheGivenStatusFilters
      API.
    link: https://developer.cisco.com/docs/dna-center/#!count-of-network-devices-for-the-given-status-filters
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.count_of_network_devices_for_the_given_status_filters,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceImages/count,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Images Count
  cisco.dnac.network_device_images_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    managementAddress: string
    networkDeviceImageStatus: string
    networkDeviceUpdateStatus: string
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
