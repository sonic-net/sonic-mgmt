#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_device_claim
short_description: Resource module for Pnp Device Claim
description:
  - Manage operation create of the resource Pnp Device
    Claim.
  - Claims one of more devices with specified workflow.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  authorizationNeeded:
    description: Flag to enable/disable PnP device authorization.
      (true means enable).
    type: bool
  configFileUrl:
    description: Pnp Device Claim's configFileUrl.
    type: str
  configId:
    description: Pnp Device Claim's configId.
    type: str
  deviceClaimList:
    description: Pnp Device Claim's deviceClaimList.
    elements: dict
    suboptions:
      configList:
        description: Pnp Device Claim's configList.
        elements: dict
        suboptions:
          configId:
            description: Pnp Device Claim's configId.
            type: str
          configParameters:
            description: Pnp Device Claim's configParameters.
            elements: dict
            suboptions:
              key:
                description: Pnp Device Claim's key.
                type: str
              value:
                description: Pnp Device Claim's value.
                type: str
            type: list
        type: list
      deviceId:
        description: Pnp Device Claim's deviceId.
        type: str
      licenseLevel:
        description: Pnp Device Claim's licenseLevel.
        type: str
      licenseType:
        description: Pnp Device Claim's licenseType.
        type: str
      topOfStackSerialNumber:
        description: Pnp Device Claim's topOfStackSerialNumber.
        type: str
    type: list
  fileServiceId:
    description: Pnp Device Claim's fileServiceId.
    type: str
  imageId:
    description: Pnp Device Claim's imageId.
    type: str
  imageUrl:
    description: Pnp Device Claim's imageUrl.
    type: str
  populateInventory:
    description: PopulateInventory flag.
    type: bool
  projectId:
    description: Pnp Device Claim's projectId.
    type: str
  workflowId:
    description: Pnp Device Claim's workflowId.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) ClaimDevice
    description: Complete reference of the ClaimDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!claim-device
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.claim_device,
  - Paths used are
    post /dna/intent/api/v1/onboarding/pnp-device/claim,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.pnp_device_claim:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    authorizationNeeded: true
    configFileUrl: string
    configId: string
    deviceClaimList:
      - configList:
          - configId: string
            configParameters:
              - key: string
                value: string
        deviceId: string
        licenseLevel: string
        licenseType: string
        topOfStackSerialNumber: string
    fileServiceId: string
    imageId: string
    imageUrl: string
    populateInventory: true
    projectId: string
    workflowId: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "jsonArrayResponse": [
        {}
      ],
      "jsonResponse": {},
      "message": "string",
      "statusCode": 0
    }
"""
