#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_delete_without_cleanup
short_description: Resource module for Network Devices
  Delete Without Cleanup
description:
  - Manage operation create of the resource Network
    Devices Delete Without Cleanup. - > This API endpoint
    facilitates the deletion of a network device without
    performing configuration cleanup on the device.
    To delete a device via API, you must have permission
    to provision the network device. Although the API
    operation does not change the device configuration,
    removing a device without cleaning up its configuration
    could lead to a network behaviour that is not consistent
    with the configurations that are known to the system.
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
      DeleteANetworkDeviceWithoutConfigurationCleanup
    description: Complete reference of the DeleteANetworkDeviceWithoutConfigurationCleanup
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-a-network-device-without-configuration-cleanup
notes:
  - SDK Method used are
    devices.Devices.delete_a_network_device_without_configuration_cleanup,
  - Paths used are
    post /dna/intent/api/v1/networkDevices/deleteWithoutCleanup,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_devices_delete_without_cleanup:
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
