#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: http_read_credential
short_description: Resource module for Http Read Credential
description:
  - Manage operations create and update of the resource
    Http Read Credential.
  - Adds HTTP read credentials.
  - Updates global HTTP Read credential.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  comments:
    description: Comments to identify the HTTP(S) Read
      credential.
    type: str
  credentialType:
    description: Credential type to identify the application
      that uses the HTTP(S) Read credential.
    type: str
  description:
    description: Description for HTTP(S) Read Credential.
    type: str
  id:
    description: Id of the HTTP(S) Read Credential in
      UUID format.
    type: str
  instanceTenantId:
    description: Deprecated.
    type: str
  instanceUuid:
    description: Deprecated.
    type: str
  password:
    description: HTTP(S) Read Password.
    type: str
  port:
    description: HTTP(S) Port. Valid port should be
      in the range of 1 to 65535.
    type: int
  secure:
    description: Flag for HTTPS Read.
    type: bool
  username:
    description: HTTP(S) Read Username.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Discovery
      CreateHTTPReadCredentials
    description: Complete reference of the CreateHTTPReadCredentials
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-http-read-credentials
  - name: Cisco DNA Center documentation for Discovery
      UpdateHTTPReadCredential
    description: Complete reference of the UpdateHTTPReadCredential
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-http-read-credential
notes:
  - SDK Method used are
    discovery.Discovery.create_http_read_credentials,
    discovery.Discovery.update_http_read_credential,
  - Paths used are
    post /dna/intent/api/v1/global-credential/http-read,
    put /dna/intent/api/v1/global-credential/http-read,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.http_read_credential:
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
    id: string
    instanceTenantId: string
    instanceUuid: string
    password: string
    port: 0
    secure: true
    username: string
- name: Update all
  cisco.dnac.http_read_credential:
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
    id: string
    instanceTenantId: string
    instanceUuid: string
    password: string
    port: 0
    secure: true
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
