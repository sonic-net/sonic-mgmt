#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_device_claim_to_site
short_description: Resource module for Pnp Device Claim
  To Site
description:
  - Manage operation create of the resource Pnp Device
    Claim To Site. - > Claim a device based on Catalyst
    Center Site-based design process. Some required
    parameters differ based on device platform.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  configInfo:
    description: Pnp Device Claim To Site's configInfo.
    suboptions:
      configId:
        description: Config Id.
        type: str
      configParameters:
        description: Pnp Device Claim To Site's configParameters.
        elements: dict
        suboptions:
          key:
            description: Key.
            type: str
          value:
            description: Value.
            type: str
        type: list
    type: dict
    version_added: 4.2.0
  deviceId:
    description: Device Id.
    type: str
  gateway:
    description: For CatalystWLC/MobilityExpress.
    type: str
    version_added: 6.4.0
  hostname:
    description: Hostname to configure on Device.
    type: str
    version_added: 4.2.0
  imageInfo:
    description: Pnp Device Claim To Site's imageInfo.
    suboptions:
      imageId:
        description: Image Id.
        type: str
      skip:
        description: Skip.
        type: bool
    type: dict
    version_added: 4.2.0
  ipInterfaceName:
    description: For Catalyst 9800 WLC.
    type: str
    version_added: 6.4.0
  rfProfile:
    description: For Access Points.
    type: str
    version_added: 6.1.0
  sensorProfile:
    description: For Sensors.
    type: str
  siteId:
    description: Site Id.
    type: str
  staticIP:
    description: For CatalystWLC/MobilityExpress.
    type: str
    version_added: 6.4.0
  subnetMask:
    description: For CatalystWLC/MobilityExpress.
    type: str
  type:
    description: Type.
    type: str
  vlanId:
    description: For Catalyst 9800 WLC.
    type: str
    version_added: 6.4.0
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) ClaimADeviceToASite
    description: Complete reference of the ClaimADeviceToASite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!claim-a-device-to-a-site
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.claim_a_device_to_a_site,
  - Paths used are
    post /dna/intent/api/v1/onboarding/pnp-device/site-claim,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.pnp_device_claim_to_site:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    configInfo:
      configId: string
      configParameters:
        - key: string
          value: string
    deviceId: string
    gateway: string
    hostname: string
    imageInfo:
      imageId: string
      skip: true
    ipInterfaceName: string
    rfProfile: string
    sensorProfile: string
    siteId: string
    staticIP: string
    subnetMask: string
    type: string
    vlanId: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": "string",
      "version": "string"
    }
"""
