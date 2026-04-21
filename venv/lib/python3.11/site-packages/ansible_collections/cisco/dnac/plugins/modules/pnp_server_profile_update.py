#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_server_profile_update
short_description: Resource module for Pnp Server Profile
  Update
description:
  - Manage operation update of the resource Pnp Server
    Profile Update. - > Updates the PnP Server profile
    in a registered Virtual Account in the PnP database.
    The response payload returns the updated smart &
    virtual account info.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  ccoUser:
    description: Cco User.
    type: str
  profile:
    description: Pnp Server Profile Update's profile.
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
        description: Cert.
        type: str
      makeDefault:
        description: Make Default.
        type: bool
      name:
        description: Name.
        type: str
      port:
        description: Port.
        type: float
      profileId:
        description: Profile Id.
        type: str
      proxy:
        description: Proxy.
        type: bool
    type: dict
  smartAccountId:
    description: Smart Account Id.
    type: str
  virtualAccountId:
    description: Virtual Account Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) UpdatePnPServerProfile
    description: Complete reference of the UpdatePnPServerProfile
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-pn-p-server-profile
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.update_pnp_server_profile,
  - Paths used are
    put /dna/intent/api/v1/onboarding/pnp-settings/savacct,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.pnp_server_profile_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    ccoUser: string
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
