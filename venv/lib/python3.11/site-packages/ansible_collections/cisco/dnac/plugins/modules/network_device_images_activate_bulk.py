#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_images_activate_bulk
short_description: Resource module for Network Device
  Images Activate Bulk
description:
  - Manage operation create of the resource Network
    Device Images Activate Bulk. - > This API initiates
    the process of updating the software image on the
    given network devices. Providing value for the `installedImages`
    in request payload will initiate both distribution
    and activation of the images. At the end of this
    process, only the images which are part of `installedImages`
    will be running on the network devices. To monitor
    the progress and completion of the update task,
    call the GET API `/dna/intent/api/v1/networkDeviceImageUpdates?parentId={taskId}`,
    where `taskId` is from the response of the current
    endpoint.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Network Device Images Activate Bulk's
      payload.
    elements: dict
    suboptions:
      compatibleFeatures:
        description: Network Device Images Activate
          Bulk's compatibleFeatures.
        elements: dict
        suboptions:
          key:
            description: Name of the compatible feature.
            type: str
          value:
            description: Feature that can be enabled
              or disabled.
            type: str
        type: list
      id:
        description: Network device identifier.
        type: str
      installedImages:
        description: Network Device Images Activate
          Bulk's installedImages.
        elements: dict
        suboptions:
          id:
            description: Software image identifier.
            type: str
        type: list
      networkValidationIds:
        description: List of unique identifiers of custom
          network device validations.
        elements: str
        type: list
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) BulkUpdateImagesOnNetworkDevices
    description: Complete reference of the BulkUpdateImagesOnNetworkDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!bulk-update-images-on-network-devices
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.bulk_update_images_on_network_devices,
  - Paths used are
    post /dna/intent/api/v1/networkDeviceImages/activate/bulk,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_device_images_activate_bulk:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    payload:
      - compatibleFeatures:
          - key: string
            value: string
        id: string
        installedImages:
          - id: string
        networkValidationIds:
          - string
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
