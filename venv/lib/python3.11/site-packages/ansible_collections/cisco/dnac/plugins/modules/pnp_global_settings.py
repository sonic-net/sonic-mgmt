#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_global_settings
short_description: Resource module for Pnp Global Settings
description:
  - Manage operation update of the resource Pnp Global
    Settings.
  - Updates the user's list of global PnP settings.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  acceptEula:
    description: Accept Eula.
    type: str
  defaultProfile:
    description: Pnp Global Settings's defaultProfile.
    suboptions:
      cert:
        description: Cert.
        type: str
      fqdnAddresses:
        description: Fqdn Addresses.
        elements: str
        type: list
      ipAddresses:
        description: Ip Addresses.
        elements: str
        type: list
      port:
        description: Port.
        type: str
      proxy:
        description: Proxy.
        type: str
    type: dict
  id:
    description: Id.
    type: str
  savaMappingList:
    description: Pnp Global Settings's savaMappingList.
    elements: dict
    suboptions:
      ccoUser:
        description: Cco User.
        type: str
      expiry:
        description: Expiry.
        type: str
      profile:
        description: Pnp Global Settings's profile.
        suboptions:
          addressFqdn:
            description: Address Fqdn.
            type: str
          addressIpV4:
            description: Address Ip V4.
            type: str
          cert:
            description: Cert.
            type: str
          makeDefault:
            description: Make Default.
            type: str
          name:
            description: Name.
            type: str
          port:
            description: Port.
            type: str
          profileId:
            description: Profile Id.
            type: str
          proxy:
            description: Proxy.
            type: str
        type: dict
      smartAccountId:
        description: Smart Account Id.
        type: str
      virtualAccountId:
        description: Virtual Account Id.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) UpdatePnPGlobalSettings
    description: Complete reference of the UpdatePnPGlobalSettings
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-pn-p-global-settings
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.update_pnp_global_settings,
  - Paths used are
    put /dna/intent/api/v1/onboarding/pnp-settings,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.pnp_global_settings:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    acceptEula: string
    defaultProfile:
      cert: string
      fqdnAddresses:
        - string
      ipAddresses:
        - string
      port: string
      proxy: string
    id: string
    savaMappingList:
      - ccoUser: string
        expiry: string
        profile:
          addressFqdn: string
          addressIpV4: string
          cert: string
          makeDefault: string
          name: string
          port: string
          profileId: string
          proxy: string
        smartAccountId: string
        virtualAccountId: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "savaMappingList": [
        {
          "syncStatus": "string",
          "syncStartTime": 0,
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
          "lastSync": 0,
          "tenantId": "string",
          "profile": {
            "port": 0,
            "addressIpV4": "string",
            "addressFqdn": "string",
            "profileId": "string",
            "proxy": true,
            "makeDefault": true,
            "cert": "string",
            "name": "string"
          },
          "token": "string",
          "expiry": 0,
          "ccoUser": "string",
          "smartAccountId": "string",
          "virtualAccountId": "string",
          "autoSyncPeriod": 0,
          "syncResultStr": "string"
        }
      ],
      "taskTimeOuts": {
        "imageDownloadTimeOut": 0,
        "configTimeOut": 0,
        "generalTimeOut": 0
      },
      "tenantId": "string",
      "aaaCredentials": {
        "password": "string",
        "username": "string"
      },
      "defaultProfile": {
        "fqdnAddresses": [
          "string"
        ],
        "proxy": true,
        "cert": "string",
        "ipAddresses": [
          "string"
        ],
        "port": 0
      },
      "acceptEula": true,
      "id": "string",
      "version": 0
    }
"""
