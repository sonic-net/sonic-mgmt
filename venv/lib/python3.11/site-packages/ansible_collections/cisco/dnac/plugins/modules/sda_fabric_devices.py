#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabric_devices
short_description: Resource module for Sda Fabric Devices
description:
  - Manage operations create, update and delete of the
    resource Sda Fabric Devices.
  - Adds fabric devices based on user input.
  - Deletes a fabric device based on id.
  - Deletes fabric devices based on user input.
  - Updates fabric devices based on user input.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deviceRoles:
    description: DeviceRoles query parameter. Device
      roles of the fabric device. Allowed values are
      CONTROL_PLANE_NODE, EDGE_NODE, BORDER_NODE, WIRELESS_CONTROLLER_NODE.
    type: str
  fabricId:
    description: FabricId query parameter. ID of the
      fabric this device belongs to.
    type: str
  id:
    description: Id path parameter. ID of the fabric
      device.
    type: str
  networkDeviceId:
    description: NetworkDeviceId query parameter. Network
      device ID of the fabric device.
    type: str
  payload:
    description: Sda Fabric Devices's payload.
    elements: dict
    suboptions:
      borderDeviceSettings:
        description: Sda Fabric Devices's borderDeviceSettings.
        suboptions:
          borderTypes:
            description: List of the border types of
              the fabric device. Allowed values are
              LAYER_2, LAYER_3.
            elements: str
            type: list
          layer3Settings:
            description: Sda Fabric Devices's layer3Settings.
            suboptions:
              borderPriority:
                description: Border priority of the
                  fabric border device. Allowed range
                  is 1-9. A lower value indicates higher
                  priority. E.g., a priority of 1 takes
                  precedence over 5. Default priority
                  would be set to 10.
                type: int
              importExternalRoutes:
                description: Set this to import external
                  routes from other routing protocols
                  (such as BGP) to the fabric control
                  plane. (updating this field is not
                  allowed).
                type: bool
              isDefaultExit:
                description: Set this to make the fabric
                  border device the gateway of last
                  resort for this site. Any unknown
                  traffic will be sent to this fabric
                  border device from edge nodes. (updating
                  this field is not allowed).
                type: bool
              localAutonomousSystemNumber:
                description: BGP Local autonomous system
                  number of the fabric border device.
                  Allowed range is 1 to 4294967295.
                  (updating this field is not allowed).
                type: str
              prependAutonomousSystemCount:
                description: Prepend autonomous system
                  count of the fabric border device.
                  Allowed range is 1 to 10.
                type: int
            type: dict
        type: dict
      deviceRoles:
        description: List of the roles of the fabric
          device. Allowed values are CONTROL_PLANE_NODE,
          EDGE_NODE, BORDER_NODE, WIRELESS_CONTROLLER_NODE.
          (updating this field is not allowed).
        elements: str
        type: list
      fabricId:
        description: ID of the fabric of this fabric
          device. (updating this field is not allowed).
        type: str
      id:
        description: ID of the fabric device. (updating
          this field is not allowed).
        type: str
      networkDeviceId:
        description: Network device ID of the fabric
          device. (updating this field is not allowed).
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddFabricDevices
    description: Complete reference of the AddFabricDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-fabric-devices
  - name: Cisco DNA Center documentation for SDA DeleteFabricDeviceById
    description: Complete reference of the DeleteFabricDeviceById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-fabric-device-by-id
  - name: Cisco DNA Center documentation for SDA DeleteFabricDevices
    description: Complete reference of the DeleteFabricDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-fabric-devices
  - name: Cisco DNA Center documentation for SDA UpdateFabricDevices
    description: Complete reference of the UpdateFabricDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-fabric-devices
notes:
  - SDK Method used are
    sda.Sda.add_fabric_devices,
    sda.Sda.delete_fabric_device_by_id,
    sda.Sda.update_fabric_devices,
  - Paths used are
    post /dna/intent/api/v1/sda/fabricDevices,
    delete /dna/intent/api/v1/sda/fabricDevices,
    delete
    /dna/intent/api/v1/sda/fabricDevices/{id},
    put /dna/intent/api/v1/sda/fabricDevices,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.sda_fabric_devices:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - borderDeviceSettings:
          borderTypes:
            - string
          layer3Settings:
            borderPriority: 0
            importExternalRoutes: true
            isDefaultExit: true
            localAutonomousSystemNumber: string
            prependAutonomousSystemCount: 0
        deviceRoles:
          - string
        fabricId: string
        id: string
        networkDeviceId: string
- name: Delete all
  cisco.dnac.sda_fabric_devices:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    deviceRoles: string
    fabricId: string
    networkDeviceId: string
- name: Create
  cisco.dnac.sda_fabric_devices:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - borderDeviceSettings:
          borderTypes:
            - string
          layer3Settings:
            borderPriority: 0
            importExternalRoutes: true
            isDefaultExit: true
            localAutonomousSystemNumber: string
            prependAutonomousSystemCount: 0
        deviceRoles:
          - string
        fabricId: string
        networkDeviceId: string
- name: Delete by id
  cisco.dnac.sda_fabric_devices:
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
