#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sites_site_id_wireless_settings_flex_connect_aaa_override
short_description: Resource module for Sites Site Id
  Wireless Settings Flex Connect Aaa Override
description:
  - Manage operations update and delete of the resource
    Sites Site Id Wireless Settings Flex Connect Aaa
    Override.
  - This API allows the user to delete AAA Override
    VLAN settings at the given site level.
  - This API allows the user to update an existing AAA
    Override VLAN setting at the given site level.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Sites Site Id Wireless Settings Flex
      Connect Aaa Override's payload.
    elements: dict
    suboptions:
      vlanId:
        description: The VLAN ID is a identifier used
          to uniquely distinguish a Virtual Local Area
          Network (VLAN) within a network.Range is 1
          to 4094.
        type: int
      vlanName:
        description: The VLAN NAME is a label assigned
          to a Virtual Local Area Network (VLAN) to
          identify and differentiate it within a network.Max
          allowed characters is 32.
        type: str
    type: list
  removeOverrideInHierarchy:
    description: RemoveOverrideInHierarchy query parameter.
      If the siteId pertains to a Global or non-Global
      site (e.g., Global, Area, Building, or Floor)
      and removeOverrideInHierarchy is set to true,
      this API will remove the override from the specified
      siteId and any child sites for the same AAA Override
      VLAN. If removeOverrideInHierarchy is set to false,
      the API will only remove the override from the
      specified siteId only, leaving any overrides for
      the AAA Override VLAN at child sites unaffected.
    type: bool
  siteId:
    description: SiteId path parameter. Site Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      DeleteAAAOverrideVlanSettingsBySite
    description: Complete reference of the DeleteAAAOverrideVlanSettingsBySite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-aaa-override-vlan-settings-by-site
  - name: Cisco DNA Center documentation for Wireless
      UpdateAAAOverrideVlanSettingsBySite
    description: Complete reference of the UpdateAAAOverrideVlanSettingsBySite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-aaa-override-vlan-settings-by-site
notes:
  - SDK Method used are
    wireless.Wireless.delete_aaa_override_vlan_settings_by_site,
    wireless.Wireless.update_aaa_override_vlan_settings_by_site,
  - Paths used are
    delete /dna/intent/api/v1/sites/{siteId}/wirelessSettings/flexConnectAaaOverride,
    put /dna/intent/api/v1/sites/{siteId}/wirelessSettings/flexConnectAaaOverride,
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.sites_site_id_wireless_settings_flex_connect_aaa_override:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    removeOverrideInHierarchy: true
    siteId: string
- name: Update all
  cisco.dnac.sites_site_id_wireless_settings_flex_connect_aaa_override:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - vlanId: 0
        vlanName: string
    siteId: string
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
