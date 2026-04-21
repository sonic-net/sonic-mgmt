#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_controllers_primary_managed_ap_locations_info
short_description: Information module for Wireless Controllers
  Primary Managed Ap Locations
description:
  - Get all Wireless Controllers Primary Managed Ap
    Locations.
  - Retrieves all the details of Primary Managed AP
    locations associated with the specific Wireless
    Controller.
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
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. Default is 500 if not
        specified. Maximum allowed limit is 500.
    type: float
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetPrimaryManagedAPLocationsForSpecificWirelessController
    description: Complete reference of the GetPrimaryManagedAPLocationsForSpecificWirelessController
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-primary-managed-ap-locations-for-specific-wireless-controller
notes:
  - SDK Method used are
    wireless.Wireless.get_primary_managed_ap_locations_for_specific_wireless_controller,
  - Paths used are
    get /dna/intent/api/v1/wirelessControllers/{networkDeviceId}/primaryManagedApLocations,
"""

EXAMPLES = r"""
---
- name: Get all Wireless Controllers Primary Managed
    Ap Locations
  cisco.dnac.wireless_controllers_primary_managed_ap_locations_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    limit: 0
    offset: 0
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
        "managedApLocations": [
          {
            "siteId": "string",
            "siteNameHierarchy": "string"
          }
        ]
      },
      "version": "string"
    }
"""
