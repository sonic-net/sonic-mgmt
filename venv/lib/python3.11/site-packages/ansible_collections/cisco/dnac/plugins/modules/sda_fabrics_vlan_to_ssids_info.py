#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabrics_vlan_to_ssids_info
short_description: Information module for Sda Fabrics
  Vlan To Ssids
description:
  - Get all Sda Fabrics Vlan To Ssids.
  - It will return all vlan to SSID mapping across all
    the fabric site.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  limit:
    description:
      - >
        Limit query parameter. Return only this many
        IP Pool to SSID Mapping. Default is 500 if not
        specified. Maximum allowed limit is 500.
    type: int
  offset:
    description:
      - Offset query parameter. Number of records to
        skip for pagination.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Fabric
      Wireless ReturnsAllTheFabricSitesThatHaveVLANToSSIDMapping
    description: Complete reference of the ReturnsAllTheFabricSitesThatHaveVLANToSSIDMapping
      API.
    link: https://developer.cisco.com/docs/dna-center/#!returns-all-the-fabric-sites-that-have-vlan-to-ssid-mapping
notes:
  - SDK Method used are
    fabric_wireless.FabricWireless.returns_all_the_fabric_sites_that_have_vlan_to_ssid_mapping,
  - Paths used are
    get /dna/intent/api/v1/sda/fabrics/vlanToSsids,
"""

EXAMPLES = r"""
---
- name: Get all Sda Fabrics Vlan To Ssids
  cisco.dnac.sda_fabrics_vlan_to_ssids_info:
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
          "fabricId": "string",
          "vlanDetails": [
            {
              "vlanName": "string",
              "ssidDetails": [
                {
                  "name": "string",
                  "securityGroupTag": "string"
                }
              ]
            }
          ]
        }
      ],
      "version": "string"
    }
"""
