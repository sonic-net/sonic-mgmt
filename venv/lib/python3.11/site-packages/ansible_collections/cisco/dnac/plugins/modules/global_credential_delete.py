#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: global_credential_delete
short_description: Resource module for Global Credential
  Delete
description:
  - Manage operation delete of the resource Global Credential
    Delete.
  - Deletes global credential for the given ID.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  globalCredentialId:
    description: GlobalCredentialId path parameter.
      ID of global-credential.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Discovery
      DeleteGlobalCredentialsById
    description: Complete reference of the DeleteGlobalCredentialsById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-global-credentials-by-id
notes:
  - SDK Method used are
    discovery.Discovery.delete_global_credentials_by_id,
  - Paths used are
    delete /dna/intent/api/v1/global-credential/{globalCredentialId},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.global_credential_delete:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    globalCredentialId: string
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
