#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_controllers_managed_ap_locations_count_info
short_description: Information module for Wireless Controllers
  Managed Ap Locations Count
description:
  - Get all Wireless Controllers Managed Ap Locations
    Count. - > Retrieves the count of Managed AP locations,
    including Primary Managed AP Locations, Secondary
    Managed AP Locations, and Anchor Managed AP Locations,
    associated with the specific Wireless Controller.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  networkDeviceId:
    description:
      - >
        NetworkDeviceId path parameter. Obtain the network
        device ID value by using the API call GET /dna/intent/api/v1/network-device/ip-address/${ipAddress}.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetManagedAPLocationsCountForSpecificWirelessController
    description: Complete reference of the GetManagedAPLocationsCountForSpecificWirelessController
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-managed-ap-locations-count-for-specific-wireless-controller
notes:
  - SDK Method used are
    wireless.Wireless.get_managed_ap_locations_count_for_specific_wireless_controller,
  - Paths used are
    get /dna/intent/api/v1/wirelessControllers/{networkDeviceId}/managedApLocations/count,
"""

EXAMPLES = r"""
---
- name: Get all Wireless Controllers Managed Ap Locations
    Count
  cisco.dnac.wireless_controllers_managed_ap_locations_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
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
      "response": {
        "primaryManagedApLocationsCount": 0,
        "secondaryManagedApLocationsCount": 0,
        "anchorManagedApLocationsCount": 0
      },
      "version": "string"
    }
"""
