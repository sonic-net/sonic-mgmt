#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: authentication_import_certificate_p12
short_description: Resource module for Authentication
  Import Certificate P12
description:
  - Manage operation create of the resource Authentication
    Import Certificate P12.
  - This API enables a user to import a PKCS12 certificate
    bundle for the controller and/or disaster recovery.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  listOfUsers:
    description: ListOfUsers query parameter. Specify
      whether the certificate will be used for controller
      ("server"), disaster recovery ("ipsec") or both
      ("server, ipsec"). If no value is provided, the
      default value taken will be "server".
    elements: str
    type: list
  p12FilePath:
    description: P12 file absolute path.
    type: str
  p12Password:
    description: P12Password query parameter. The password
      for PKCS12 certificate bundle.
    type: str
  pkPassword:
    description: PkPassword query parameter. Password
      for encrypted private key.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Authentication
      Management ImportCertificateP12
    description: Complete reference of the ImportCertificateP12
      API.
    link: https://developer.cisco.com/docs/dna-center/#!import-certificate-p-12
notes:
  - SDK Method used are
    authentication_management.AuthenticationManagement.import_certificate_p12,
  - Paths used are
    post /dna/intent/api/v1/certificate-p12,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.authentication_import_certificate_p12:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    listOfUsers: []
    p12FilePath: /tmp/uploads/Test-242.p12
    p12Password: string
    pkPassword: string
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
