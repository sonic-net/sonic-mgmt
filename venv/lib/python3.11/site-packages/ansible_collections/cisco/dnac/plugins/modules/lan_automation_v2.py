#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: lan_automation_v2
short_description: Resource module for Lan Automation
  V2
description:
  - Manage operation create of the resource Lan Automation
    V2. - > Invoke V2 LAN Automation Start API, which
    supports optional auto-stop processing feature based
    on the provided timeout or a specific device list,
    or both. The stop processing will be executed automatically
    when either of the cases is satisfied, without specifically
    calling the stop API. The V2 API behaves similarly
    to V1 if no timeout or device list is provided,
    and the user needs to call the stop API for LAN
    Automation stop processing. With the V2 API, the
    user can also specify the level up to which the
    devices can be LAN automated.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Lan Automation V2's payload.
    elements: dict
    suboptions:
      discoveredDeviceSiteNameHierarchy:
        description: Discovered device site name.
        type: str
      discoveryDevices:
        description: Lan Automation V2's discoveryDevices.
        elements: dict
        suboptions:
          deviceHostName:
            description: Hostname of the device.
            type: str
          deviceManagementIPAddress:
            description: Management IP Address of the
              device.
            type: str
          deviceSerialNumber:
            description: Serial number of the device.
            type: str
          deviceSiteNameHierarchy:
            description: "Site name hierarchy for the
              device, must be a child site of the discoveredDeviceSiteNameHierarchy
              or same if it's not area type."
            type: str
        type: list
      discoveryLevel:
        description: Level below primary seed device
          upto which the new devices will be LAN Automated
          by this session, level + seed = tier. Supported
          range for level is 1-5, default level is 2.
        type: int
      discoveryTimeout:
        description: Discovery timeout in minutes. Until
          this time, the stop processing will not be
          triggered. Any device contacting after the
          provided discovery timeout will not be processed,
          and a device reset and reload will be attempted
          to bring it back to the PnP agent state before
          process completion. The supported timeout
          range is in minutes 20-10080. If both timeout
          and discovery devices list are provided, the
          stop processing will be attempted whichever
          happens earlier. Users can always use the
          LAN Automation delete API to force stop processing.
        type: int
      hostNameFileId:
        description: Use /dna/intent/api/v1/file/namespace/nw_orch
          API to get the file ID for the already uploaded
          file in the nw_orch namespace.
        type: str
      hostNamePrefix:
        description: Host name prefix assigned to the
          discovered device.
        type: str
      ipPools:
        description: Lan Automation V2's ipPools.
        elements: dict
        suboptions:
          ipPoolName:
            description: Name of the IP pool.
            type: str
          ipPoolRole:
            description: Role of the IP pool. Supported
              roles are MAIN_POOL and PHYSICAL_LINK_POOL.
            type: str
        type: list
      isisDomainPwd:
        description: IS-IS domain password in plain
          text.
        type: str
      multicastEnabled:
        description: Enable underlay native multicast.
        type: bool
      peerDeviceManagmentIPAddress:
        description: Peer seed management IP address.
        type: str
      primaryDeviceInterfaceNames:
        description: The list of interfaces on primary
          seed via which the discovered devices are
          connected.
        elements: str
        type: list
      primaryDeviceManagmentIPAddress:
        description: Primary seed management IP address.
        type: str
      redistributeIsisToBgp:
        description: Advertise LAN Automation summary
          route into BGP.
        type: bool
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for LAN Automation
      LANAutomationStartV2
    description: Complete reference of the LANAutomationStartV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!l-an-automation-start-v-2
notes:
  - SDK Method used are
    lan_automation.LanAutomation.lan_automation_start_v2,
  - Paths used are
    post /dna/intent/api/v2/lan-automation,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.lan_automation_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    payload:
      - discoveredDeviceSiteNameHierarchy: string
        discoveryDevices:
          - deviceHostName: string
            deviceManagementIPAddress: string
            deviceSerialNumber: string
            deviceSiteNameHierarchy: string
        discoveryLevel: 0
        discoveryTimeout: 0
        hostNameFileId: string
        hostNamePrefix: string
        ipPools:
          - ipPoolName: string
            ipPoolRole: string
        isisDomainPwd: string
        multicastEnabled: true
        peerDeviceManagmentIPAddress: string
        primaryDeviceInterfaceNames:
          - string
        primaryDeviceManagmentIPAddress: string
        redistributeIsisToBgp: true
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
