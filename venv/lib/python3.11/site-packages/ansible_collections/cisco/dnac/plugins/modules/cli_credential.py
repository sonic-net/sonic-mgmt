#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: cli_credential
short_description: Resource module for Cli Credential
description:
  - Manage operations create and update of the resource
    Cli Credential.
  - Adds global CLI credential.
  - Updates global CLI credentials.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  comments:
    description: Comments to identify the CLI credential.
    type: str
  credentialType:
    description: Credential type to identify the application
      that uses the CLI credential.
    type: str
  description:
    description: Description for CLI Credentials.
    type: str
  enablePassword:
    description: CLI Enable Password.
    type: str
  id:
    description: Id of the CLI Credential in UUID format.
    type: str
  instanceTenantId:
    description: Deprecated.
    type: str
  instanceUuid:
    description: Deprecated.
    type: str
  password:
    description: CLI Password.
    type: str
  username:
    description: CLI Username.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Discovery
      CreateCLICredentials
    description: Complete reference of the CreateCLICredentials
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-cli-credentials
  - name: Cisco DNA Center documentation for Discovery
      UpdateCLICredentials
    description: Complete reference of the UpdateCLICredentials
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-cli-credentials
notes:
  - SDK Method used are
    discovery.Discovery.create_cli_credentials,
    discovery.Discovery.update_cli_credentials,
  - Paths used are
    post /dna/intent/api/v1/global-credential/cli,
    put /dna/intent/api/v1/global-credential/cli,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.cli_credential:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    comments: string
    credentialType: string
    description: string
    enablePassword: string
    id: string
    instanceTenantId: string
    instanceUuid: string
    password: string
    username: string
- name: Create
  cisco.dnac.cli_credential:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    comments: string
    credentialType: string
    description: string
    enablePassword: string
    id: string
    instanceTenantId: string
    instanceUuid: string
    password: string
    username: string
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
