#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabrics_vlan_to_ssids_fabric_id_count_info
short_description: Information module for Sda Fabrics
  Vlan To Ssids Fabric Id Count
description:
  - Get all Sda Fabrics Vlan To Ssids Fabric Id Count.
    - > Returns the count of VLANs mapped to SSIDs in
    a Fabric Site. The 'fabricId' represents the Fabric
    ID of a particular Fabric Site.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  fabricId:
    description:
      - FabricId path parameter. The 'fabricId' represents
        the Fabric ID of a particular Fabric Site.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Fabric
      Wireless ReturnsTheCountOfVLANsMappedToSSIDsInAFabricSite
    description: Complete reference of the ReturnsTheCountOfVLANsMappedToSSIDsInAFabricSite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!returns-the-count-of-vla-ns-mapped-to-ssi-ds-in-a-fabric-site
notes:
  - SDK Method used are
    fabric_wireless.FabricWireless.returns_the_count_of_vlans_mapped_to_ssids_in_a_fabric_site,
  - Paths used are
    get /dna/intent/api/v1/sda/fabrics/{fabricId}/vlanToSsids/count,
"""

EXAMPLES = r"""
---
- name: Get all Sda Fabrics Vlan To Ssids Fabric Id
    Count
  cisco.dnac.sda_fabrics_vlan_to_ssids_fabric_id_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    fabricId: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "count": 0
      },
      "version": "string"
    }
"""
