#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: topology_vlan_details_info
short_description: Information module for Topology Vlan
  Details
description:
  - Get all Topology Vlan Details.
  - Returns the list of VLAN names that are involved
    in a loop as identified by the Spanning Tree Protocol.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Topology
      GetVLANDetails
    description: Complete reference of the GetVLANDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-vlan-details
notes:
  - SDK Method used are
    topology.Topology.get_vlan_details,
  - Paths used are
    get /dna/intent/api/v1/topology/vlan/vlan-names,
"""

EXAMPLES = r"""
---
- name: Get all Topology Vlan Details
  cisco.dnac.topology_vlan_details_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        "string"
      ],
      "version": "string"
    }
"""
