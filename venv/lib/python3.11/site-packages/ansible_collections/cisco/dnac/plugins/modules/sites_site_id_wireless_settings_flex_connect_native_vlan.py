#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sites_site_id_wireless_settings_flex_connect_native_vlan
short_description: Resource module for Sites Site Id
  Wireless Settings Flex Connect Native Vlan
description:
  - Manage operations update and delete of the resource
    Sites Site Id Wireless Settings Flex Connect Native
    Vlan.
  - This API allows the user to delete a Native VLAN
    setting at the given site level. - > This API allows
    the user to update an existing Native VLAN setting
    at the given site level. The default value of the
    native VLAN on the device is 1 when nothing is explicitly
    set.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  nativeVlanId:
    description: Native VLAN ID is used for any untagged
      frames.Range is 1 to 4094.
    type: int
  removeOverrideInHierarchy:
    description: RemoveOverrideInHierarchy query parameter.
      If the siteId pertains to a Global or non-Global
      site (e.g., Global, Area, Building, or Floor)
      and removeOverrideInHierarchy is set to true,
      this API will remove the override from the specified
      siteId and any child sites for the same Native
      VLAN. If removeOverrideInHierarchy is set to false,
      the API will only remove the override from the
      specified siteId only, leaving any overrides for
      the Native VLAN at child sites unaffected.
    type: bool
  siteId:
    description: SiteId path parameter. Site Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      DeleteNativeVlanSettingsBySite
    description: Complete reference of the DeleteNativeVlanSettingsBySite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-native-vlan-settings-by-site
  - name: Cisco DNA Center documentation for Wireless
      UpdateNativeVlanSettingsBySite
    description: Complete reference of the UpdateNativeVlanSettingsBySite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-native-vlan-settings-by-site
notes:
  - SDK Method used are
    wireless.Wireless.delete_native_vlan_settings_by_site,
    wireless.Wireless.update_native_vlan_settings_by_site,
  - Paths used are
    delete /dna/intent/api/v1/sites/{siteId}/wirelessSettings/flexConnectNativeVlan,
    put /dna/intent/api/v1/sites/{siteId}/wirelessSettings/flexConnectNativeVlan,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.sites_site_id_wireless_settings_flex_connect_native_vlan:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    nativeVlanId: 0
    siteId: string
- name: Delete all
  cisco.dnac.sites_site_id_wireless_settings_flex_connect_native_vlan:
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
