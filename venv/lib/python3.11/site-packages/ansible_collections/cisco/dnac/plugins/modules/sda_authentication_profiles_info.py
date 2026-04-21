#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_authentication_profiles_info
short_description: Information module for Sda Authentication
  Profiles
description:
  - Get all Sda Authentication Profiles.
  - Returns a list of authentication profiles that match
    the provided query parameters.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  fabricId:
    description:
      - FabricId query parameter. ID of the fabric the
        authentication profile is assigned to.
    type: str
  authenticationProfileName:
    description:
      - >
        AuthenticationProfileName query parameter. Return
        only the authentication profiles with this specified
        name. Note that 'No Authentication' is not a
        valid option for this parameter.
    type: str
  isGlobalAuthenticationProfile:
    description:
      - >
        IsGlobalAuthenticationProfile query parameter.
        Set to true to return only global authentication
        profiles, or set to false to hide them. IsGlobalAuthenticationProfile
        must not be true when fabricId is provided.
    type: bool
  offset:
    description:
      - Offset query parameter. Starting record for
        pagination.
    type: int
  limit:
    description:
      - >
        Limit query parameter. Maximum number of records
        to return. The maximum number of objects supported
        in a single request is 500.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetAuthenticationProfiles
    description: Complete reference of the GetAuthenticationProfiles
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-authentication-profiles
notes:
  - SDK Method used are
    sda.Sda.get_authentication_profiles,
  - Paths used are
    get /dna/intent/api/v1/sda/authenticationProfiles,
"""

EXAMPLES = r"""
---
- name: Get all Sda Authentication Profiles
  cisco.dnac.sda_authentication_profiles_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    fabricId: string
    authenticationProfileName: string
    isGlobalAuthenticationProfile: true
    offset: 0
    limit: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "id": "string",
          "fabricId": "string",
          "authenticationProfileName": "string",
          "authenticationOrder": "string",
          "dot1xToMabFallbackTimeout": 0,
          "wakeOnLan": true,
          "numberOfHosts": "string",
          "isBpduGuardEnabled": true,
          "isVoiceVlanEnabled": true,
          "preAuthAcl": {
            "enabled": true,
            "implicitAction": "string",
            "description": "string",
            "accessContracts": [
              {
                "action": "string",
                "protocol": "string",
                "port": "string"
              }
            ]
          }
        }
      ],
      "version": "string"
    }
"""
