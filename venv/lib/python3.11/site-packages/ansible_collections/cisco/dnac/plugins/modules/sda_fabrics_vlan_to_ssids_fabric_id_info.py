#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabrics_vlan_to_ssids_fabric_id_info
short_description: Information module for Sda Fabrics
  Vlan To Ssids Fabric Id
description:
  - Get all Sda Fabrics Vlan To Ssids Fabric Id. - >
    Retrieve the VLANs and SSIDs mapped to the VLAN,
    within a Fabric Site. The 'fabricId' represents
    the Fabric ID of a particular Fabric Site.
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
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. Default is 500 if not
        specified. Maximum allowed limit is 500.
    type: int
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Fabric
      Wireless RetrieveTheVLANsAndSSIDsMappedToTheVLANWithinAFabricSite
    description: Complete reference of the RetrieveTheVLANsAndSSIDsMappedToTheVLANWithinAFabricSite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-the-vla-ns-and-ssi-ds-mapped-to-the-vlan-within-a-fabric-site
notes:
  - SDK Method used are
    fabric_wireless.FabricWireless.retrieve_the_vlans_and_ssids_mapped_to_the_vlan_within_a_fabric_site,
  - Paths used are
    get /dna/intent/api/v1/sda/fabrics/{fabricId}/vlanToSsids,
"""

EXAMPLES = r"""
---
- name: Get all Sda Fabrics Vlan To Ssids Fabric Id
  cisco.dnac.sda_fabrics_vlan_to_ssids_fabric_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    limit: 0
    offset: 0
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
      "response": [
        {
          "vlanName": "string",
          "ssidDetails": [
            {
              "name": "string",
              "securityGroupTag": "string"
            }
          ]
        }
      ],
      "version": "string"
    }
"""
