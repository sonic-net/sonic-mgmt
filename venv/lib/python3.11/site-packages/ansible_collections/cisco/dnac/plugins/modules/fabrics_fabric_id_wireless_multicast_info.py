#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: fabrics_fabric_id_wireless_multicast_info
short_description: Information module for Fabrics Fabric
  Id Wireless Multicast
description:
  - Get all Fabrics Fabric Id Wireless Multicast. -
    > Retrieves the current Software-Defined Access
    SDA Wireless Multicast setting for a specified fabric
    site. The setting indicates whether multicast is
    enabled true or disabled false. For optimal performance,
    ensure wired multicast is also enabled.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  fabricId:
    description:
      - >
        FabricId path parameter. The unique identifier
        of the fabric site for which the multicast setting
        is being requested. The identifier should be
        in the format of a UUID. The 'fabricId' can
        be obtained using the api /dna/intent/api/v1/sda/fabricSites.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Fabric
      Wireless GetSDAWirelessMulticast
    description: Complete reference of the GetSDAWirelessMulticast
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-sda-wireless-multicast
notes:
  - SDK Method used are
    fabric_wireless.FabricWireless.get_sda_wireless_multicast,
  - Paths used are
    get /dna/intent/api/v1/sda/fabrics/{fabricId}/wirelessMulticast,
"""

EXAMPLES = r"""
---
- name: Get all Fabrics Fabric Id Wireless Multicast
  cisco.dnac.fabrics_fabric_id_wireless_multicast_info:
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
        "multicastEnabled": true
      },
      "version": "string"
    }
"""
