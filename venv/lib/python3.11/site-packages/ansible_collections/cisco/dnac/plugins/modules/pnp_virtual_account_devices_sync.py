#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_virtual_account_devices_sync
short_description: Resource module for Pnp Virtual Account
  Devices Sync
description:
  - Manage operation create of the resource Pnp Virtual
    Account Devices Sync. - > Synchronizes the device
    info from the given smart account & virtual account
    with the PnP database. The response payload returns
    a list of synced devices Deprecated .
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  autoSyncPeriod:
    description: Pnp Virtual Account Devices Sync's
      autoSyncPeriod.
    type: int
  ccoUser:
    description: Pnp Virtual Account Devices Sync's
      ccoUser.
    type: str
  expiry:
    description: Pnp Virtual Account Devices Sync's
      expiry.
    type: int
  lastSync:
    description: Pnp Virtual Account Devices Sync's
      lastSync.
    type: int
  profile:
    description: Pnp Virtual Account Devices Sync's
      profile.
    suboptions:
      addressFqdn:
        description: Pnp Virtual Account Devices Sync's
          addressFqdn.
        type: str
      addressIpV4:
        description: Pnp Virtual Account Devices Sync's
          addressIpV4.
        type: str
      cert:
        description: Pnp Virtual Account Devices Sync's
          cert.
        type: str
      makeDefault:
        description: MakeDefault flag.
        type: bool
      name:
        description: Pnp Virtual Account Devices Sync's
          name.
        type: str
      port:
        description: Pnp Virtual Account Devices Sync's
          port.
        type: int
      profileId:
        description: Pnp Virtual Account Devices Sync's
          profileId.
        type: str
      proxy:
        description: Proxy flag.
        type: bool
    type: dict
  smartAccountId:
    description: Pnp Virtual Account Devices Sync's
      smartAccountId.
    type: str
  syncResult:
    description: Pnp Virtual Account Devices Sync's
      syncResult.
    suboptions:
      syncList:
        description: Pnp Virtual Account Devices Sync's
          syncList.
        elements: dict
        suboptions:
          deviceSnList:
            description: Pnp Virtual Account Devices
              Sync's deviceSnList.
            elements: str
            type: list
          syncType:
            description: Pnp Virtual Account Devices
              Sync's syncType.
            type: str
        type: list
      syncMsg:
        description: Pnp Virtual Account Devices Sync's
          syncMsg.
        type: str
    type: dict
  syncResultStr:
    description: Pnp Virtual Account Devices Sync's
      syncResultStr.
    type: str
  syncStartTime:
    description: Pnp Virtual Account Devices Sync's
      syncStartTime.
    type: int
  syncStatus:
    description: Pnp Virtual Account Devices Sync's
      syncStatus.
    type: str
  tenantId:
    description: Pnp Virtual Account Devices Sync's
      tenantId.
    type: str
  token:
    description: Pnp Virtual Account Devices Sync's
      token.
    type: str
  virtualAccountId:
    description: Pnp Virtual Account Devices Sync's
      virtualAccountId.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) SyncVirtualAccountDevices
    description: Complete reference of the SyncVirtualAccountDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!sync-virtual-account-devices
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.sync_virtual_account_devices,
  - Paths used are
    post /dna/intent/api/v1/onboarding/pnp-device/vacct-sync,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.pnp_virtual_account_devices_sync:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    autoSyncPeriod: 0
    ccoUser: string
    expiry: 0
    lastSync: 0
    profile:
      addressFqdn: string
      addressIpV4: string
      cert: string
      makeDefault: true
      name: string
      port: 0
      profileId: string
      proxy: true
    smartAccountId: string
    syncResult:
      syncList:
        - deviceSnList:
            - string
          syncType: string
      syncMsg: string
    syncResultStr: string
    syncStartTime: 0
    syncStatus: string
    tenantId: string
    token: string
    virtualAccountId: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "virtualAccountId": "string",
      "autoSyncPeriod": 0,
      "syncResultStr": "string",
      "profile": {
        "proxy": true,
        "makeDefault": true,
        "port": 0,
        "profileId": "string",
        "name": "string",
        "addressIpV4": "string",
        "cert": "string",
        "addressFqdn": "string"
      },
      "ccoUser": "string",
      "syncResult": {
        "syncList": [
          {
            "syncType": "string",
            "deviceSnList": [
              "string"
            ]
          }
        ],
        "syncMsg": "string"
      },
      "token": "string",
      "syncStartTime": 0,
      "lastSync": 0,
      "tenantId": "string",
      "smartAccountId": "string",
      "expiry": 0,
      "syncStatus": "string"
    }
"""
