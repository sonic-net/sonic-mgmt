#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: netconf_credential
short_description: Resource module for Netconf Credential
description:
  - Manage operations create and update of the resource
    Netconf Credential.
  - Adds global netconf credentials.
  - Updates global netconf credentials.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  comments:
    description: Comments to identify the netconf credential.
    type: str
  credentialType:
    description: Credential type to identify the application
      that uses the netconf credential.
    type: str
  description:
    description: Description for Netconf Credentials.
    type: str
  id:
    description: Id of the Netconf Credential in UUID
      format.
    type: str
  instanceTenantId:
    description: Deprecated.
    type: str
  instanceUuid:
    description: Deprecated.
    type: str
  netconfPort:
    description: Netconf port on the device. Valid port
      should be in the range of 1 to 65535.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Discovery
      CreateNetconfCredentials
    description: Complete reference of the CreateNetconfCredentials
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-netconf-credentials
  - name: Cisco DNA Center documentation for Discovery
      UpdateNetconfCredentials
    description: Complete reference of the UpdateNetconfCredentials
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-netconf-credentials
notes:
  - SDK Method used are
    discovery.Discovery.create_netconf_credentials,
    discovery.Discovery.update_netconf_credentials,
  - Paths used are
    post /dna/intent/api/v1/global-credential/netconf,
    put /dna/intent/api/v1/global-credential/netconf,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.netconf_credential:
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
    netconfPort: string
- name: Create
  cisco.dnac.netconf_credential:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - comments: string
        credentialType: string
        description: string
        id: string
        instanceTenantId: string
        instanceUuid: string
        netconfPort: string
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
