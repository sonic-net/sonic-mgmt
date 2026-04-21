#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_images_validations_id
short_description: Resource module for Network Device
  Images Validations Id
description:
  - Manage operations update and delete of the resource
    Network Device Images Validations Id.
  - Delete the custom network device validation.
  - Update the custom network device validation details.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  cli:
    description: Edit the Command line interface (CLI).
      Validate the CLI - Cisco DevNet https //developer.cisco.com/docs/dna-center/2-3-7/run-read-only-commands-on-devices-to-get-their-real-time-co...
    type: str
  description:
    description: Details of the network device validation.
    type: str
  id:
    description: Id path parameter. Unique identifier
      of network device validation.
    type: str
  productSeriesOrdinals:
    description: The custom check will be mapped to
      the product series and devices that belong to
      this series. These devices will consume this check
      when triggered.
    elements: float
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) DeleteCustomNetworkDeviceValidation
    description: Complete reference of the DeleteCustomNetworkDeviceValidation
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-custom-network-device-validation
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) UpdateCustomNetworkDeviceValidation
    description: Complete reference of the UpdateCustomNetworkDeviceValidation
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-custom-network-device-validation
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.delete_custom_network_device_validation,
    software_image_management_swim.SoftwareImageManagementSwim.update_custom_network_device_validation,
  - Paths used are
    delete /dna/intent/api/v1/networkDeviceImages/validations/{id},
    put /dna/intent/api/v1/networkDeviceImages/validations/{id},
"""

EXAMPLES = r"""
---
- name: Update by id
  cisco.dnac.network_device_images_validations_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    cli: string
    description: string
    id: string
    productSeriesOrdinals:
      - 0
- name: Delete by id
  cisco.dnac.network_device_images_validations_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
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
