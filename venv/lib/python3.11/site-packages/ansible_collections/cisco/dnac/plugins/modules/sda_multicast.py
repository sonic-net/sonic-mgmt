#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_multicast
short_description: Resource module for Sda Multicast
description:
  - Manage operations create and delete of the resource
    Sda Multicast.
  - Add multicast in SDA fabric.
  - Delete multicast from SDA fabric.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  multicastMethod:
    description: Multicast Method.
    type: str
  multicastType:
    description: Multicast Type.
    type: str
  multicastVnInfo:
    description: Sda Multicast's multicastVnInfo.
    elements: dict
    suboptions:
      externalRpIpAddress:
        description: ExternalRpIpAddress, required if
          multicastType is asm_with_external_rp.
        type: str
      internalRpIpAddress:
        description: InternalRpIpAddress, required if
          multicastType is asm_with_internal_rp.
        elements: str
        type: list
      ipPoolName:
        description: Ip Pool Name, that is reserved
          to Fabric Site.
        type: str
      ssmInfo:
        description: Sda Multicast's ssmInfo.
        elements: dict
        suboptions:
          ssmGroupRange:
            description: Valid SSM group range ip address(e.g.,
              230.0.0.0).
            type: str
          ssmWildcardMask:
            description: Valid SSM Wildcard Mask ip
              address(e.g.,0.255.255.255).
            type: str
        type: list
      virtualNetworkName:
        description: Virtual Network Name, that is associated
          to Fabric Site.
        type: str
    type: list
  siteNameHierarchy:
    description: Full path of sda Fabric Site.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddMulticastInSDAFabric
    description: Complete reference of the AddMulticastInSDAFabric
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-multicast-in-sda-fabric
  - name: Cisco DNA Center documentation for SDA DeleteMulticastFromSDAFabric
    description: Complete reference of the DeleteMulticastFromSDAFabric
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-multicast-from-sda-fabric
notes:
  - SDK Method used are
    sda.Sda.add_multicast_in_sda_fabric,
    sda.Sda.delete_multicast_from_sda_fabric,
  - Paths used are
    post /dna/intent/api/v1/business/sda/multicast,
    delete /dna/intent/api/v1/business/sda/multicast,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.sda_multicast:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    multicastMethod: string
    multicastType: string
    multicastVnInfo:
      - externalRpIpAddress: string
        internalRpIpAddress:
          - string
        ipPoolName: string
        ssmInfo:
          - ssmGroupRange: string
            ssmWildcardMask: string
        virtualNetworkName: string
    siteNameHierarchy: string
- name: Delete all
  cisco.dnac.sda_multicast:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
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
