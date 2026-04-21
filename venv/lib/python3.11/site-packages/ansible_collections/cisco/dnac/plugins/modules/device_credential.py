#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_credential
short_description: Resource module for Device Credential
description:
  - Manage operations create, update and delete of the
    resource Device Credential.
  - API to create device credentials.
  - Delete device credential.
  - API to update device credentials.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Global credential
      id.
    type: str
  settings:
    description: Device Credential's settings.
    suboptions:
      cliCredential:
        description: Device Credential's cliCredential.
        elements: dict
        suboptions:
          description:
            description: Name or description for CLI
              credential.
            type: str
          enablePassword:
            description: Enable password for CLI credential.
            type: str
          password:
            description: Password for CLI credential.
            type: str
          username:
            description: User name for CLI credential.
            type: str
        type: list
      httpsRead:
        description: Device Credential's httpsRead.
        elements: dict
        suboptions:
          name:
            description: Name or description of http
              read credential.
            type: str
          password:
            description: Password for http read credential.
            type: str
          port:
            description: Port for http read credential.
            type: float
          username:
            description: User name of the http read
              credential.
            type: str
        type: list
      httpsWrite:
        description: Device Credential's httpsWrite.
        elements: dict
        suboptions:
          name:
            description: Name or description of http
              write credential.
            type: str
          password:
            description: Password for http write credential.
            type: str
          port:
            description: Port for http write credential.
            type: float
          username:
            description: User name of the http write
              credential.
            type: str
        type: list
      snmpV2cRead:
        description: Device Credential's snmpV2cRead.
        elements: dict
        suboptions:
          description:
            description: Description for snmp v2 read.
            type: str
          readCommunity:
            description: Ready community for snmp v2
              read credential.
            type: str
        type: list
      snmpV2cWrite:
        description: Device Credential's snmpV2cWrite.
        elements: dict
        suboptions:
          description:
            description: Description for snmp v2 write.
            type: str
          writeCommunity:
            description: Write community for snmp v2
              write credential.
            type: str
        type: list
      snmpV3:
        description: Device Credential's snmpV3.
        elements: dict
        suboptions:
          authPassword:
            description: Authentication password for
              snmpv3 credential.
            type: str
          authType:
            description: Authentication type for snmpv3
              credential.
            type: str
          description:
            description: Name or description for SNMPV3
              credential.
            type: str
          privacyPassword:
            description: Privacy password for snmpv3
              credential.
            type: str
          privacyType:
            description: Privacy type for snmpv3 credential.
            type: str
          snmpMode:
            description: Mode for snmpv3 credential.
            type: str
          username:
            description: User name for SNMPv3 credential.
            type: str
        type: list
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings CreateDeviceCredentials
    description: Complete reference of the CreateDeviceCredentials
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-device-credentials
  - name: Cisco DNA Center documentation for Network
      Settings DeleteDeviceCredential
    description: Complete reference of the DeleteDeviceCredential
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-device-credential
  - name: Cisco DNA Center documentation for Network
      Settings UpdateDeviceCredentials
    description: Complete reference of the UpdateDeviceCredentials
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-device-credentials
notes:
  - SDK Method used are
    network_settings.NetworkSettings.create_device_credentials,
    network_settings.NetworkSettings.delete_device_credential,
    network_settings.NetworkSettings.update_device_credentials,
  - Paths used are
    post /dna/intent/api/v1/device-credential,
    delete /dna/intent/api/v1/device-credential/{id},
    put /dna/intent/api/v1/device-credential,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.device_credential:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    settings:
      cliCredential:
        - description: string
          enablePassword: string
          password: string
          username: string
      httpsRead:
        - name: string
          password: string
          port: 0
          username: string
      httpsWrite:
        - name: string
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
- name: Update all
  cisco.dnac.device_credential:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    settings:
      cliCredential:
        description: string
        enablePassword: string
        id: string
        password: string
        username: string
      httpsRead:
        id: string
        name: string
        password: string
        port: string
        username: string
      httpsWrite:
        id: string
        name: string
        password: string
        port: string
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
- name: Delete by id
  cisco.dnac.device_credential:
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
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
"""
