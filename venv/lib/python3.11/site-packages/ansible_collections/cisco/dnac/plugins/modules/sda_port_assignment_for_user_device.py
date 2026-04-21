#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_port_assignment_for_user_device
short_description: Resource module for Sda Port Assignment
  For User Device
description:
  - Manage operations create and delete of the resource
    Sda Port Assignment For User Device.
  - Add Port assignment for user device in SDA Fabric.
  - Delete Port assignment for user device in SDA Fabric.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  authenticateTemplateName:
    description: Authenticate TemplateName associated
      with siteNameHierarchy.
    type: str
    version_added: 4.0.0
  dataIpAddressPoolName:
    description: Ip Pool Name, that is assigned to virtual
      network with traffic type as DATA(can't be empty
      if voiceIpAddressPoolName is empty).
    type: str
    version_added: 4.0.0
  deviceManagementIpAddress:
    description: DeviceManagementIpAddress query parameter.
    type: str
  interfaceDescription:
    description: User defined text message for port
      assignment.
    type: str
    version_added: 4.0.0
  interfaceName:
    description: InterfaceName query parameter.
    type: str
  interfaceNames:
    description: List of Interface Names on the Edge
      Node Device. E.g."GigabitEthernet1/0/3","GigabitEthernet1/0/4".
    elements: str
    type: list
  scalableGroupName:
    description: Scalable Group name associated with
      VN.
    type: str
    version_added: 4.0.0
  siteNameHierarchy:
    description: Complete Path of SD-Access Fabric Site.
    type: str
    version_added: 4.0.0
  voiceIpAddressPoolName:
    description: Ip Pool Name, that is assigned to virtual
      network with traffic type as VOICE(can't be empty
      if dataIpAddressPoolName is empty).
    type: str
    version_added: 4.0.0
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddPortAssignmentForUserDeviceInSDAFabric
    description: Complete reference of the AddPortAssignmentForUserDeviceInSDAFabric
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-port-assignment-for-user-device-in-sda-fabric
  - name: Cisco DNA Center documentation for SDA DeletePortAssignmentForUserDeviceInSDAFabric
    description: Complete reference of the DeletePortAssignmentForUserDeviceInSDAFabric
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-port-assignment-for-user-device-in-sda-fabric
notes:
  - SDK Method used are
    sda.Sda.add_port_assignment_for_user_device,
    sda.Sda.delete_port_assignment_for_user_device,
  - Paths used are
    post /dna/intent/api/v1/business/sda/hostonboarding/user-device,
    delete /dna/intent/api/v1/business/sda/hostonboarding/user-device,
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.sda_port_assignment_for_user_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    deviceManagementIpAddress: string
    interfaceName: string
- name: Create
  cisco.dnac.sda_port_assignment_for_user_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    authenticateTemplateName: string
    dataIpAddressPoolName: string
    deviceManagementIpAddress: string
    interfaceDescription: string
    interfaceName: string
    interfaceNames:
      - string
    scalableGroupName: string
    siteNameHierarchy: string
    voiceIpAddressPoolName: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "status": "string",
      "description": "string",
      "taskId": "string",
      "taskStatusUrl": "string",
      "executionStatusUrl": "string",
      "executionId": "string"
    }
"""
