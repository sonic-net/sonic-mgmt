#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: credential_to_site_by_siteid_create_v2
short_description: Resource module for Credential To
  Site By Siteid Create V2
description:
  - Manage operation create of the resource Credential
    To Site By Siteid Create V2.
  - API to assign Device Credential to a site.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  cliId:
    description: CLI Credential Id.
    type: str
  httpRead:
    description: HTTP(S) Read Credential Id.
    type: str
  httpWrite:
    description: HTTP(S) Write Credential Id.
    type: str
  siteId:
    description: SiteId path parameter. Site Id to assign
      credential.
    type: str
  snmpV2ReadId:
    description: SNMPv2c Read Credential Id.
    type: str
  snmpV2WriteId:
    description: SNMPv2c Write Credential Id.
    type: str
  snmpV3Id:
    description: SNMPv3 Credential Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings AssignDeviceCredentialToSiteV2
    description: Complete reference of the AssignDeviceCredentialToSiteV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!assign-device-credential-to-site-v-2
notes:
  - SDK Method used are
    network_settings.NetworkSettings.assign_device_credential_to_site_v2,
  - Paths used are
    post /dna/intent/api/v2/credential-to-site/{siteId},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.credential_to_site_by_siteid_create_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    cliId: string
    httpRead: string
    httpWrite: string
    siteId: string
    snmpV2ReadId: string
    snmpV2WriteId: string
    snmpV3Id: string
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
