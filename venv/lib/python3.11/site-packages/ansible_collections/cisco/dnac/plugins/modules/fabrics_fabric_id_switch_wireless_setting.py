#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: fabrics_fabric_id_switch_wireless_setting
short_description: Resource module for Fabrics Fabric
  Id Switch Wireless Setting
description:
  - Manage operation update of the resource Fabrics
    Fabric Id Switch Wireless Setting. - > This API
    is used to enable or disable wireless capabilities
    on switch devices, along with configuring rolling
    AP upgrades on the fabric site. Reboot action is
    required to remove wireless configurations.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  enableWireless:
    description: Enable Wireless.
    type: bool
  fabricId:
    description: FabricId path parameter. The 'fabricId'
      represents the Fabric ID of a particular Fabric
      Site. The 'fabricId' can be obtained using the
      api /dna/intent/api/v1/sda/fabricSites. Example
      e290f1ee-6c54-4b01-90e6-d701748f0851.
    type: str
  id:
    description: Network Device ID of the wireless capable
      switch.
    type: str
  rollingApUpgrade:
    description: Fabrics Fabric Id Switch Wireless Setting's
      rollingApUpgrade.
    suboptions:
      apRebootPercentage:
        description: AP Reboot Percentage. Permissible
          values - 5, 15, 25.
        type: int
      enableRollingApUpgrade:
        description: Enable Rolling Ap Upgrade.
        type: bool
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Fabric
      Wireless SwitchWirelessSettingAndRollingAPUpgradeManagement
    description: Complete reference of the SwitchWirelessSettingAndRollingAPUpgradeManagement
      API.
    link: https://developer.cisco.com/docs/dna-center/#!switch-wireless-setting-and-rolling-ap-upgrade-management
notes:
  - SDK Method used are
    fabric_wireless.FabricWireless.switch_wireless_setting_and_rolling_ap_upgrade_management,
  - Paths used are
    put /dna/intent/api/v1/sda/fabrics/{fabricId}/switchWirelessSetting,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.fabrics_fabric_id_switch_wireless_setting:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    enableWireless: true
    fabricId: string
    id: string
    rollingApUpgrade:
      apRebootPercentage: 0
      enableRollingApUpgrade: true
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
