#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: icap_settings_configuration_models
short_description: Resource module for Icap Settings
  Configuration Models
description:
  - Manage operation create of the resource Icap Settings
    Configuration Models. - > This creates an ICAP configuration
    intent for preview approval. The intent is not deployed
    to the device until further preview-approve APIs
    are applied. This API is the first step in the preview-approve
    workflow, which consists of several APIs. Skipping
    any API in the process is not recommended for a
    complete preview-approve use case. For detailed
    information about the usage of the API, please refer
    to the Open API specification document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-ICAP_APIs-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Icap Settings Configuration Models's
      payload.
    elements: dict
    suboptions:
      apId:
        description: Ap Id.
        type: str
      captureType:
        description: Capture Type.
        type: str
      clientMac:
        description: Client Mac.
        type: str
      durationInMins:
        description: Duration In Mins.
        type: int
      otaBand:
        description: Ota Band.
        type: str
      otaChannel:
        description: Ota Channel.
        type: int
      otaChannelWidth:
        description: Ota Channel Width.
        type: int
      slot:
        description: Slot.
        elements: float
        type: list
      wlcId:
        description: Wlc Id.
        type: str
    type: list
  previewDescription:
    description: PreviewDescription query parameter.
      The ICAP intent's preview-deploy description string.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sensors
      CreatesAnICAPConfigurationIntentForPreviewApprove
    description: Complete reference of the CreatesAnICAPConfigurationIntentForPreviewApprove
      API.
    link: https://developer.cisco.com/docs/dna-center/#!creates-an-icap-configuration-intent-for-preview-approve
notes:
  - SDK Method used are
    sensors.Sensors.creates_an_i_cap_configuration_intent_for_preview_approve,
  - Paths used are
    post /dna/intent/api/v1/icapSettings/configurationModels,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.icap_settings_configuration_models:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    payload:
      - apId: string
        captureType: string
        clientMac: string
        durationInMins: 0
        otaBand: string
        otaChannel: 0
        otaChannelWidth: 0
        slot:
          - 0
        wlcId: string
    previewDescription: string
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
