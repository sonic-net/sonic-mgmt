#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: snmpv2_read_community_credential
short_description: Resource module for Snmpv2 Read Community
  Credential
description:
  - Manage operations create and update of the resource
    Snmpv2 Read Community Credential.
  - Adds global SNMP read community.
  - Updates global SNMP read community.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  comments:
    description: Comments to identify the credential.
    type: str
  credentialType:
    description: Credential type to identify the application
      that uses the credential.
    type: str
  description:
    description: Name/Description of the credential.
    type: str
  instanceUuid:
    description: Credential UUID.
    type: str
  readCommunity:
    description: SNMP read community. NO!$DATA!$ for
      no value change.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Discovery
      CreateSNMPReadCommunity
    description: Complete reference of the CreateSNMPReadCommunity
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-snmp-read-community
  - name: Cisco DNA Center documentation for Discovery
      UpdateSNMPReadCommunity
    description: Complete reference of the UpdateSNMPReadCommunity
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-snmp-read-community
notes:
  - SDK Method used are
    discovery.Discovery.create_snmp_read_community,
    discovery.Discovery.update_snmp_read_community,
  - Paths used are
    post /dna/intent/api/v1/global-credential/snmpv2-read-community,
    put /dna/intent/api/v1/global-credential/snmpv2-read-community,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.snmpv2_read_community_credential:
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
    instanceUuid: string
    readCommunity: string
- name: Create
  cisco.dnac.snmpv2_read_community_credential:
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
    readCommunity: string
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
