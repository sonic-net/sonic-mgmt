#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_unassign_from_site_apply
short_description: Resource module for Network Devices
  Unassign From Site Apply
description:
  - Manage operation create of the resource Network
    Devices Unassign From Site Apply. - > Unassign unprovisioned
    network devices from their site. If device controllability
    is enabled, it will be triggered once device unassigned
    from site successfully. Device Controllability can
    be enabled/disabled using `/dna/intent/api/v1/networkDevices/deviceControllability/settings`.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deviceIds:
    description: Network device Ids, ranging from a
      minimum of 1 to a maximum of 100.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      UnassignNetworkDevicesFromSites
    description: Complete reference of the UnassignNetworkDevicesFromSites
      API.
    link: https://developer.cisco.com/docs/dna-center/#!unassign-network-devices-from-sites
notes:
  - SDK Method used are
    site_design.SiteDesign.unassign_network_devices_from_sites,
  - Paths used are
    post /dna/intent/api/v1/networkDevices/unassignFromSite/apply,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_devices_unassign_from_site_apply:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    deviceIds:
      - string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": {
        "url": "string",
        "taskId": "string"
      }
    }
"""
