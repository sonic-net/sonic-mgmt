#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_delete_with_cleanup
short_description: Resource module for Network Devices
  Delete With Cleanup
description:
  - Manage operation create of the resource Network
    Devices Delete With Cleanup.
  - This API endpoint facilitates the deletion of a
    network device after performing configuration cleanup
    on the device.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: The unique identifier of the network
      device to be deleted.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      DeleteNetworkDeviceWithConfigurationCleanup
    description: Complete reference of the DeleteNetworkDeviceWithConfigurationCleanup
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-network-device-with-configuration-cleanup
notes:
  - SDK Method used are
    devices.Devices.delete_network_device_with_configuration_cleanup,
  - Paths used are
    post /dna/intent/api/v1/networkDevices/deleteWithCleanup,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_devices_delete_with_cleanup:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
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
