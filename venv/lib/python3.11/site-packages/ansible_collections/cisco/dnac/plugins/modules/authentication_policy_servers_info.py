#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: authentication_policy_servers_info
short_description: Information module for Authentication
  Policy Servers
description:
  - Get all Authentication Policy Servers.
  - API to get Authentication and Policy Servers.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  isIseEnabled:
    description:
      - IsIseEnabled query parameter. Valid values are
        true, false.
    type: bool
  state_:
    description:
      - State query parameter. Valid values are ACTIVE,
        DELETED, FAILED, INACTIVE, INPROGRESS, RBAC-FAILURE,
        RBAC-SUCCESS.
    type: str
  role:
    description:
      - Role query parameter. Authentication and Policy
        Server Role (Example primary, secondary).
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for System
      Settings GetAuthenticationAndPolicyServers
    description: Complete reference of the GetAuthenticationAndPolicyServers
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-authentication-and-policy-servers
notes:
  - SDK Method used are
    system_settings.SystemSettings.get_authentication_and_policy_servers,
  - Paths used are
    get /dna/intent/api/v1/authentication-policy-servers,
"""

EXAMPLES = r"""
---
- name: Get all Authentication Policy Servers
  cisco.dnac.authentication_policy_servers_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    isIseEnabled: true
    state_: string
    role: string
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
          "ipAddress": "string",
          "sharedSecret": "string",
          "protocol": "string",
          "role": "string",
          "port": 0,
          "authenticationPort": 0,
          "accountingPort": 0,
          "retries": 0,
          "timeoutSeconds": 0,
          "isIseEnabled": true,
          "instanceUuid": "string",
          "state": "string",
          "ciscoIseDtos": [
            {
              "subscriberName": "string",
              "description": "string",
              "password": "string",
              "userName": "string",
              "fqdn": "string",
              "ipAddress": "string",
              "trustState": "string",
              "instanceUuid": "string",
              "sshkey": "string",
              "type": "string",
              "failureReason": "string",
              "role": "string",
              "externalCiscoIseIpAddrDtos": {
                "type": "string",
                "externalCiscoIseIpAddresses": [
                  {
                    "externalIpAddress": "string"
                  }
                ]
              }
            }
          ],
          "encryptionScheme": "string",
          "messageKey": "string",
          "encryptionKey": "string",
          "useDnacCertForPxgrid": true,
          "iseEnabled": true,
          "pxgridEnabled": true,
          "rbacUuid": "string",
          "multiDnacEnabled": true
        }
      ],
      "version": "string"
    }
"""
