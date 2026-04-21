#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: iot_non_fabric_rep_rings
short_description: Resource module for Iot Non Fabric
  Rep Rings
description:
  - Manage operation create of the resource Iot Non
    Fabric Rep Rings. - > This API configures a REP
    ring on NON-FABRIC deployment. The input payload
    contains the following fields - ringName unique
    ring name , rootNetworkDeviceId Network device ID
    of the root node of the REP Ring and rootNeighbourNetworkDeviceIds
    Network device IDs of the two immediate neighbour
    devices of the root node of the REP Ring. The networkDeviceId
    is the instanceUuid attribute in the response of
    API - /dna/intent/api/v1/networkDevices.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deploymentMode:
    description: Deployment mode of the configured REP
      ring.
    type: str
  ringName:
    description: Unique name of REP ring to be configured.
    type: str
  rootNeighbourNetworkDeviceIds:
    description: It contains the network device IDs
      of the immediate neighboring ring members of the
      root node. API `/dna/intent/api/v1/networkDevices`
      can be used to get the list of networkDeviceIds
      of the neighbors , `instanceUuid` attribute in
      the response contains rootNeighbourNetworkDeviceIds.
    elements: str
    type: list
  rootNetworkDeviceId:
    description: RootNetworkDeviceId is the network
      device ID of the root node in the REP ring. API
      `/dna/intent/api/v1/networkDevices` can be used
      to get the rootNetworkDeviceId , `instanceUuid`
      attribute in the response contains rootNetworkDeviceId.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Industrial
      Configuration ConfigureAREPRingOnNONFABRICDeployment
    description: Complete reference of the ConfigureAREPRingOnNONFABRICDeployment
      API.
    link: https://developer.cisco.com/docs/dna-center/#!configure-arep-ring-on-nonfabric-deployment
notes:
  - SDK Method used are
    industrial_configuration.IndustrialConfiguration.configure_a_r_e_p_ring_on_n_o_n_f_a_b_r_i_c_deployment,
  - Paths used are
    post /dna/intent/api/v1/iot/nonFabric/repRings,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.iot_non_fabric_rep_rings:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    deploymentMode: string
    ringName: string
    rootNeighbourNetworkDeviceIds:
      - string
    rootNetworkDeviceId: string
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
