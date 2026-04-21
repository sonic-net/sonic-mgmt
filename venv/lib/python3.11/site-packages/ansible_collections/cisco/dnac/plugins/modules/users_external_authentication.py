#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: users_external_authentication
short_description: Resource module for Users External
  Authentication
description:
  - Manage operation create of the resource Users External
    Authentication.
  - Enable or disable external authentication in the
    System.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  enable:
    description: Enable/disable External Authentication.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for User and
      Roles ManageExternalAuthenticationSettingAPI
    description: Complete reference of the ManageExternalAuthenticationSettingAPI
      API.
    link: https://developer.cisco.com/docs/dna-center/#!manage-external-authentication-setting-api
notes:
  - SDK Method used are
    user_and_roles.UserandRoles.manage_external_authentication_setting_api,
  - Paths used are
    post /dna/system/api/v1/users/external-authentication,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.users_external_authentication:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    enable: true
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "message": "string"
    }
"""
