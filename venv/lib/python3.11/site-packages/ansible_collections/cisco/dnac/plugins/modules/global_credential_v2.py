#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: global_credential_v2
short_description: Resource module for Global Credential
  V2
description:
  - Manage operations create, update and delete of the
    resource Global Credential V2. - > API to create
    new global credentials. Multiple credentials of
    various types can be passed at once. Please refer
    sample Request Body for more information.
  - Delete a global credential. Only 'id' of the credential
    has to be passed. - > API to update device credentials.
    Multiple credentials can be passed at once, but
    only a single credential of a given type can be
    passed at once. Please refer sample Request Body
    for more information.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  cliCredential:
    description: Global Credential V2's cliCredential.
    suboptions:
      description:
        description: Description for CLI credential.
        type: str
      enablePassword:
        description: CLI Enable Password.
        type: str
      id:
        description: Id of the CLI Credential in UUID
          format.
        type: str
      password:
        description: CLI Password.
        type: str
      username:
        description: CLI Username.
        type: str
    type: dict
  httpsRead:
    description: Global Credential V2's httpsRead.
    suboptions:
      description:
        description: Description for HTTP(S) Read Credentials.
        type: str
      id:
        description: Id of the HTTP(S) Read Credential
          in UUID format.
        type: str
      password:
        description: HTTP(S) Read Password.
        type: str
      port:
        description: HTTP(S) Port.
        type: int
      username:
        description: HTTP(S) Read Username.
        type: str
    type: dict
  httpsWrite:
    description: Global Credential V2's httpsWrite.
    suboptions:
      description:
        description: Description for HTTP(S) Write Credentials.
        type: str
      id:
        description: Id of the HTTP(S) Read Credential
          in UUID format.
        type: str
      password:
        description: HTTP(S) Write Password.
        type: str
      port:
        description: HTTP(S) Port.
        type: int
      username:
        description: HTTP(S) Write Username.
        type: str
    type: dict
  id:
    description: Id path parameter. Global Credential
      id.
    type: str
  snmpV2cRead:
    description: Global Credential V2's snmpV2cRead.
    suboptions:
      description:
        description: Description for Snmp RO community.
        type: str
      id:
        description: Id of the SNMP Read Credential
          in UUID format.
        type: str
      readCommunity:
        description: Snmp RO community.
        type: str
    type: dict
  snmpV2cWrite:
    description: Global Credential V2's snmpV2cWrite.
    suboptions:
      description:
        description: Description for Snmp RW community.
        type: str
      id:
        description: Id of the SNMP Write Credential
          in UUID format.
        type: str
      writeCommunity:
        description: Snmp RW community.
        type: str
    type: dict
  snmpV3:
    description: Global Credential V2's snmpV3.
    suboptions:
      authPassword:
        description: Auth Password for SNMP V3.
        type: str
      authType:
        description: SNMP auth protocol. SHA' or 'MD5'.
        type: str
      description:
        description: Description for Snmp V3 Credential.
        type: str
      id:
        description: Id of the SNMP V3 Credential in
          UUID format.
        type: str
      privacyPassword:
        description: Privacy Password for SNMP privacy.
        type: str
      privacyType:
        description: SNMP privacy protocol. 'AES128','AES192','AES256'.
        type: str
      snmpMode:
        description: Mode of SNMP. 'AUTHPRIV' or 'AUTHNOPRIV'
          or 'NOAUTHNOPRIV'.
        type: str
      username:
        description: SNMP V3 Username.
        type: str
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Discovery
      CreateGlobalCredentialsV2
    description: Complete reference of the CreateGlobalCredentialsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-global-credentials-v-2
  - name: Cisco DNA Center documentation for Discovery
      DeleteGlobalCredentialV2
    description: Complete reference of the DeleteGlobalCredentialV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-global-credential-v-2
  - name: Cisco DNA Center documentation for Discovery
      UpdateGlobalCredentialsV2
    description: Complete reference of the UpdateGlobalCredentialsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-global-credentials-v-2
notes:
  - SDK Method used are
    discovery.Discovery.create_global_credentials_v2,
    discovery.Discovery.delete_global_credential_v2,
    discovery.Discovery.update_global_credentials_v2,
  - Paths used are
    post /dna/intent/api/v2/global-credential,
    delete /dna/intent/api/v2/global-credential/{id},
    put /dna/intent/api/v2/global-credential,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.global_credential_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    cliCredential:
      description: string
      enablePassword: string
      id: string
      password: string
      username: string
    httpsRead:
      description: string
      id: string
      password: string
      port: 0
      username: string
    httpsWrite:
      description: string
      id: string
      password: string
      port: 0
      username: string
    snmpV2cRead:
      description: string
      id: string
      readCommunity: string
    snmpV2cWrite:
      description: string
      id: string
      writeCommunity: string
    snmpV3:
      authPassword: string
      authType: string
      description: string
      id: string
      privacyPassword: string
      privacyType: string
      snmpMode: string
      username: string
- name: Create
  cisco.dnac.global_credential_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    cliCredential:
      - description: string
        enablePassword: string
        password: string
        username: string
    httpsRead:
      - description: string
        password: string
        port: 0
        username: string
    httpsWrite:
      - description: string
        password: string
        port: 0
        username: string
    snmpV2cRead:
      - description: string
        readCommunity: string
    snmpV2cWrite:
      - description: string
        writeCommunity: string
    snmpV3:
      - authPassword: string
        authType: string
        description: string
        privacyPassword: string
        privacyType: string
        snmpMode: string
        username: string
- name: Delete by id
  cisco.dnac.global_credential_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
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
