#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_virtual_account_add
short_description: Resource module for Pnp Virtual Account
  Add
description:
  - Manage operation create of the resource Pnp Virtual
    Account Add. - > Registers a Smart Account, Virtual
    Account and the relevant server profile info with
    the PnP System & database. The devices present in
    the registered virtual account are synced with the
    PnP database as well. The response payload returns
    the new profile.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  autoSyncPeriod:
    description: Pnp Virtual Account Add's autoSyncPeriod.
    type: int
  ccoUser:
    description: Pnp Virtual Account Add's ccoUser.
    type: str
  expiry:
    description: Pnp Virtual Account Add's expiry.
    type: int
  lastSync:
    description: Pnp Virtual Account Add's lastSync.
    type: int
  profile:
    description: Pnp Virtual Account Add's profile.
    suboptions:
      addressFqdn:
        description: Required when cluster is configured
          with fully qualified domain name (FQDN).
        type: str
      addressIpV4:
        description: Required when cluster is configured
          with IPv4.
        type: str
      addressIpV6:
        description: Required when cluster is configured
          with IPv6.
        type: str
      cert:
        description: Pnp Virtual Account Add's cert.
        type: str
      makeDefault:
        description: MakeDefault flag.
        type: bool
      name:
        description: Pnp Virtual Account Add's name.
        type: str
      port:
        description: Pnp Virtual Account Add's port.
        type: int
      profileId:
        description: Pnp Virtual Account Add's profileId.
        type: str
      proxy:
        description: Proxy flag.
        type: bool
    type: dict
  smartAccountId:
    description: Pnp Virtual Account Add's smartAccountId.
    type: str
  syncResult:
    description: Pnp Virtual Account Add's syncResult.
    suboptions:
      syncList:
        description: Pnp Virtual Account Add's syncList.
        elements: dict
        suboptions:
          deviceSnList:
            description: Pnp Virtual Account Add's deviceSnList.
            elements: str
            type: list
          syncType:
            description: Pnp Virtual Account Add's syncType.
            type: str
        type: list
      syncMsg:
        description: Pnp Virtual Account Add's syncMsg.
        type: str
    type: dict
  syncResultStr:
    description: Represent internal state and SHOULD
      not be used or relied upon. (Deprecated).
    type: str
  syncStartTime:
    description: Pnp Virtual Account Add's syncStartTime.
    type: int
  syncStatus:
    description: Represent internal state and SHOULD
      not be used or relied upon. (Deprecated).
    type: str
  tenantId:
    description: Represent internal state and SHOULD
      not be used or relied upon. (Deprecated).
    type: str
  token:
    description: Represent internal state and SHOULD
      not be used or relied upon. (Deprecated).
    type: str
  virtualAccountId:
    description: Pnp Virtual Account Add's virtualAccountId.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) AddVirtualAccount
    description: Complete reference of the AddVirtualAccount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-virtual-account
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.add_virtual_account,
  - Paths used are
    post /dna/intent/api/v1/onboarding/pnp-settings/savacct,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.pnp_virtual_account_add:
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
      addressIpV6: string
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
      "syncStartTime": 0,
      "lastSync": 0,
      "tenantId": "string",
      "smartAccountId": "string",
      "expiry": 0,
      "syncStatus": "string"
    }
"""
