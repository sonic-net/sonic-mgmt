#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_provision_device_update
short_description: Resource module for Wireless Provision
  Device Update
description:
  - Manage operation update of the resource Wireless
    Provision Device Update.
  - Updates wireless provisioning.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  payload:
    description: Wireless Provision Device Update's
      payload.
    elements: dict
    suboptions:
      deviceName:
        description: Controller Name.
        type: str
      dynamicInterfaces:
        description: Wireless Provision Device Update's
          dynamicInterfaces.
        elements: dict
        suboptions:
          interfaceGateway:
            description: Interface Gateway. Required
              for AireOS.
            type: str
          interfaceIPAddress:
            description: Interface IP Address. Required
              for AireOS.
            type: str
          interfaceName:
            description: Interface Name. Required for
              AireOS and EWLC.
            type: str
          interfaceNetmaskInCIDR:
            description: Interface Netmask In CIDR.
              Required for AireOS.
            type: int
          lagOrPortNumber:
            description: Lag Or Port Number. Required
              for AireOS.
            type: int
          vlanId:
            description: VLAN ID. Required for AireOS
              and EWLC.
            type: int
        type: list
      managedAPLocations:
        description: List of managed AP locations (Site
          Hierarchies).
        elements: str
        type: list
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      ProvisionUpdate
    description: Complete reference of the ProvisionUpdate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!provision-update
notes:
  - SDK Method used are
    wireless.Wireless.provision_update,
  - Paths used are
    put /dna/intent/api/v1/wireless/provision,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.wireless_provision_device_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: '{{my_headers | from_json}}'
    payload:
      - deviceName: string
        dynamicInterfaces:
          - interfaceGateway: string
            interfaceIPAddress: string
            interfaceName: string
            interfaceNetmaskInCIDR: 0
            lagOrPortNumber: 0
            vlanId: 0
        managedAPLocations:
          - string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
"""
