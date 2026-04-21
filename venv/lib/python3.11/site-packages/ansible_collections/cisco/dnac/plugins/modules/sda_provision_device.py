#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_provision_device
short_description: Resource module for Sda Provision
  Device
description:
  - Manage operations create, update and delete of the
    resource Sda Provision Device.
  - Provision Wired Device.
  - Delete provisioned Wired Device.
  - Re-Provision Wired Device.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deviceManagementIpAddress:
    description: DeviceManagementIpAddress query parameter.
      Valid IP address of the device currently provisioned
      in a fabric site.
    type: str
  siteNameHierarchy:
    description: SiteNameHierarchy of the provisioned
      device.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA ProvisionWiredDevice
    description: Complete reference of the ProvisionWiredDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!provision-wired-device
  - name: Cisco DNA Center documentation for SDA DeleteProvisionedWiredDevice
    description: Complete reference of the DeleteProvisionedWiredDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-provisioned-wired-device
  - name: Cisco DNA Center documentation for SDA ReProvisionWiredDevice
    description: Complete reference of the ReProvisionWiredDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!re-provision-wired-device
notes:
  - SDK Method used are
    sda.Sda.delete_provisioned_wired_device,
    sda.Sda.provision_wired_device,
    sda.Sda.re_provision_wired_device,
  - Paths used are
    post /dna/intent/api/v1/business/sda/provision-device,
    delete /dna/intent/api/v1/business/sda/provision-device,
    put /dna/intent/api/v1/business/sda/provision-device,
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.sda_provision_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    deviceManagementIpAddress: string
- name: Update all
  cisco.dnac.sda_provision_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    deviceManagementIpAddress: string
    siteNameHierarchy: string
- name: Create
  cisco.dnac.sda_provision_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    deviceManagementIpAddress: string
    siteNameHierarchy: string
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
