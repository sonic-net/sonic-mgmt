#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabrics_vlan_to_ssids_fabric_id
short_description: Resource module for Sda Fabrics Vlan
  To Ssids Fabric Id
description:
  - Manage operation update of the resource Sda Fabrics
    Vlan To Ssids Fabric Id. - > Add, update, or remove
    SSID mappings to a VLAN. If the payload doesn't
    contain a 'vlanName' which has SSIDs mapping done
    earlier then all the mapped SSIDs of the 'vlanName'
    is cleared. The request must include all SSIDs currently
    mapped to a VLAN, as determined by the response
    from the GET operation for the same fabricId used
    in the request. If an already-mapped SSID is not
    included in the payload, its mapping will be removed
    by this API. Conversely, if a new SSID is provided,
    it will be added to the Mapping. Ensure that any
    new SSID added is a Fabric SSID. This API can also
    be used to add a VLAN and associate the relevant
    SSIDs with it. The 'vlanName' must be 'Fabric Wireless
    Enabled' and should be part of the Fabric Site representing
    'Fabric ID' specified in the API request.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  fabricId:
    description: FabricId path parameter. The 'fabricId'
      represents the Fabric ID of a particular Fabric
      Site.
    type: str
  payload:
    description: Sda Fabrics Vlan To Ssids Fabric Id's
      payload.
    elements: dict
    suboptions:
      ssidDetails:
        description: Sda Fabrics Vlan To Ssids Fabric
          Id's ssidDetails.
        elements: dict
        suboptions:
          name:
            description: Name of the SSID.
            type: str
          securityGroupTag:
            description: Represents the name of the
              Security Group. Example Auditors, BYOD,
              Developers, etc.
            type: str
        type: list
      vlanName:
        description: Vlan Name.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Fabric
      Wireless AddUpdateOrRemoveSSIDMappingToAVLAN
    description: Complete reference of the AddUpdateOrRemoveSSIDMappingToAVLAN
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-update-or-remove-ssid-mapping-to-avlan
notes:
  - SDK Method used are
    fabric_wireless.FabricWireless.add_update_or_remove_ssid_mapping_to_a_vlan,
  - Paths used are
    put /dna/intent/api/v1/sda/fabrics/{fabricId}/vlanToSsids,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.sda_fabrics_vlan_to_ssids_fabric_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    fabricId: string
    payload:
      - ssidDetails:
          - name: string
            securityGroupTag: string
        vlanName: string
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
