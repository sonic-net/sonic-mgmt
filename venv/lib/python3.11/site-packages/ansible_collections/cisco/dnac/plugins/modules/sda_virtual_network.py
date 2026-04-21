#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_virtual_network
short_description: Resource module for Sda Virtual Network
description:
  - Manage operations create and delete of the resource
    Sda Virtual Network.
  - Add virtual network VN in SDA Fabric.
  - Delete virtual network VN from SDA Fabric.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  siteNameHierarchy:
    description: SiteNameHierarchy query parameter.
    type: str
  virtualNetworkName:
    description: VirtualNetworkName query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddVNInFabric
    description: Complete reference of the AddVNInFabric
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-vn-in-fabric
  - name: Cisco DNA Center documentation for SDA DeleteVNFromSDAFabric
    description: Complete reference of the DeleteVNFromSDAFabric
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-vn-from-sda-fabric
notes:
  - SDK Method used are
    sda.Sda.add_vn,
    sda.Sda.delete_vn,
  - Paths used are
    post /dna/intent/api/v1/business/sda/virtual-network,
    delete /dna/intent/api/v1/business/sda/virtual-network,
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.sda_virtual_network:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    siteNameHierarchy: string
    virtualNetworkName: string
- name: Create
  cisco.dnac.sda_virtual_network:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    siteNameHierarchy: string
    virtualNetworkName: string
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
