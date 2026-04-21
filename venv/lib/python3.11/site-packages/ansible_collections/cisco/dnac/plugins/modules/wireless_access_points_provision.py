#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_access_points_provision
short_description: Resource module for Wireless Access
  Points Provision
description:
  - Manage operation create of the resource Wireless
    Access Points Provision. - > This API is used to
    provision Access Points. Prerequisite Access Point
    has to be assigned to the site using the API /dna/intent/api/v1/networkDevices/assignToSite/apply.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  apZoneName:
    description: AP Zone Name. A custom AP Zone should
      be passed if no rfProfileName is provided.
    type: str
  networkDevices:
    description: Wireless Access Points Provision's
      networkDevices.
    elements: dict
    suboptions:
      beamState:
        description: Beam State (Applicable only for
          CW9179F AP models).
        type: str
      deviceId:
        description: Network device ID of access points.
        type: str
      meshRole:
        description: Mesh Role (Applicable only when
          AP is in Bridge Mode).
        type: str
    type: list
  rfProfileName:
    description: RF Profile Name. RF Profile is not
      allowed for custom AP Zones.
    type: str
  siteId:
    description: Site ID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      APProvision
    description: Complete reference of the APProvision
      API.
    link: https://developer.cisco.com/docs/dna-center/#!a-p-provision
notes:
  - SDK Method used are
    wireless.Wireless.ap_provision,
  - Paths used are
    post /dna/intent/api/v1/wirelessAccessPoints/provision,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wireless_access_points_provision:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    apZoneName: string
    networkDevices:
      - beamState: string
        deviceId: string
        meshRole: string
    rfProfileName: string
    siteId: string
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
