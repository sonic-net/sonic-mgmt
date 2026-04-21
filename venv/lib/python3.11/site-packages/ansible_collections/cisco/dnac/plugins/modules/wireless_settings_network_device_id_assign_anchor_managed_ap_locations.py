#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_network_device_id_assign_anchor_managed_ap_locations
short_description: Resource module for Wireless Settings
  Network Device Id Assign Anchor Managed Ap Locations
description:
  - Manage operation create of the resource Wireless
    Settings Network Device Id Assign Anchor Managed
    Ap Locations. - > This API allows user to assign
    Anchor Managed AP Locations for WLC by device ID.
    The payload should always be a complete list. The
    Managed AP Locations included in the payload will
    be fully processed for both addition and deletion.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  anchorManagedAPLocationsSiteIds:
    description: This API allows user to assign Anchor
      Managed AP Locations for WLC by device ID. The
      payload should always be a complete list. The
      Managed AP Locations included in the payload will
      be fully processed for both addition and deletion.
      - When anchor managed location array present then
      it will add the anchor managed locations.
    elements: str
    type: list
  networkDeviceId:
    description: NetworkDeviceId path parameter. Network
      Device ID. This value can be obtained by using
      the API call GET /dna/intent/api/v1/network-device/ip-address/${ipAddress}.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      AssignAnchorManagedAPLocationsForWLC
    description: Complete reference of the AssignAnchorManagedAPLocationsForWLC
      API.
    link: https://developer.cisco.com/docs/dna-center/#!assign-anchor-managed-ap-locations-for-wlc
notes:
  - SDK Method used are
    wireless.Wireless.assign_anchor_managed_ap_locations_for_w_l_c,
  - Paths used are
    post /dna/intent/api/v1/wirelessSettings/{networkDeviceId}/assignAnchorManagedApLocations,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wireless_settings_network_device_id_assign_anchor_managed_ap_locations:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    anchorManagedAPLocationsSiteIds:
      - string
    networkDeviceId: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
