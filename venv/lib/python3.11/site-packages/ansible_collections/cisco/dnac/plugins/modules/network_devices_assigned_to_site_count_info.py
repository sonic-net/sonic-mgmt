#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_assigned_to_site_count_info
short_description: Information module for Network Devices
  Assigned To Site Count
description:
  - Get all Network Devices Assigned To Site Count.
  - Get all network devices count under the given site
    in the network hierarchy.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description:
      - SiteId query parameter. Site Id. It must be
        area Id or building Id or floor Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      GetSiteAssignedNetworkDevicesCount
    description: Complete reference of the GetSiteAssignedNetworkDevicesCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-site-assigned-network-devices-count
notes:
  - SDK Method used are
    site_design.SiteDesign.get_site_assigned_network_devices_count,
  - Paths used are
    get /dna/intent/api/v1/networkDevices/assignedToSite/count,
"""

EXAMPLES = r"""
---
- name: Get all Network Devices Assigned To Site Count
  cisco.dnac.network_devices_assigned_to_site_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
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
