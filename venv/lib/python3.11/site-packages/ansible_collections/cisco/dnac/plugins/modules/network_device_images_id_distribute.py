#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_images_id_distribute
short_description: Resource module for Network Device
  Images Id Distribute
description:
  - Manage operation create of the resource Network
    Device Images Id Distribute. - > This API initiates
    the process of distributing the software image on
    the network device. Providing value for the `distributedImages`
    will only trigger the distribution process. To monitor
    the progress and completion of the update task,
    please call the GET API `/dna/intent/api/v1/networkDeviceImageUpdates?parentId={taskId}`,
    where `taskId` is from the response of the current
    endpoint.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  distributedImages:
    description: Network Device Images Id Distribute's
      distributedImages.
    elements: dict
    suboptions:
      id:
        description: Software image identifier.
        type: str
    type: list
  id:
    description: Id path parameter. Network device identifier.
    type: str
  networkValidationIds:
    description: List of unique identifiers of custom
      network device validations.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) DistributeImagesOnTheNetworkDevice
    description: Complete reference of the DistributeImagesOnTheNetworkDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!distribute-images-on-the-network-device
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.distribute_images_on_the_network_device,
  - Paths used are
    post /dna/intent/api/v1/networkDeviceImages/{id}/distribute,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_device_images_id_distribute:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    distributedImages:
      - id: string
    id: string
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
