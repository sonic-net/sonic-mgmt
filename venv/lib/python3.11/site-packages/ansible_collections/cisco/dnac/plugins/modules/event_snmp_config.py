#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: event_snmp_config
short_description: Resource module for Event Snmp Config
description:
  - Manage operations create and update of the resource
    Event Snmp Config.
  - Create SNMP Destination.
  - Update SNMP Destination.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  authPassword:
    description: Auth Password.
    type: str
  community:
    description: Required only if snmpVersion is V2C.
    type: str
  configId:
    description: Config Id.
    type: str
  description:
    description: Description.
    type: str
  ipAddress:
    description: Ip Address.
    type: str
  name:
    description: Name.
    type: str
  port:
    description: Port.
    type: str
  privacyPassword:
    description: Privacy Password.
    type: str
  snmpAuthType:
    description: Snmp Auth Type.
    type: str
  snmpMode:
    description: If snmpVersion is V3 it is required
      and cannot be NONE.
    type: str
  snmpPrivacyType:
    description: Snmp Privacy Type.
    type: str
  snmpVersion:
    description: Snmp Version.
    type: str
  userName:
    description: Required only if snmpVersion is V3.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Event Management
      CreateSNMPDestination
    description: Complete reference of the CreateSNMPDestination
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-snmp-destination
  - name: Cisco DNA Center documentation for Event Management
      UpdateSNMPDestination
    description: Complete reference of the UpdateSNMPDestination
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-snmp-destination
notes:
  - SDK Method used are
    event_management.EventManagement.create_snmp_destination,
    event_management.EventManagement.update_snmp_destination,
  - Paths used are
    post /dna/intent/api/v1/event/snmp-config,
    put /dna/intent/api/v1/event/snmp-config,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.event_snmp_config:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    authPassword: string
    community: string
    description: string
    ipAddress: string
    name: string
    port: string
    privacyPassword: string
    snmpAuthType: string
    snmpMode: string
    snmpPrivacyType: string
    snmpVersion: string
    userName: string
- name: Update all
  cisco.dnac.event_snmp_config:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    authPassword: string
    community: string
    configId: string
    description: string
    ipAddress: string
    name: string
    port: string
    privacyPassword: string
    snmpAuthType: string
    snmpMode: string
    snmpPrivacyType: string
    snmpVersion: string
    userName: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "errorMessage": {
        "errors": [
          {}
        ]
      },
      "apiStatus": "string",
      "statusMessage": "string"
    }
"""
