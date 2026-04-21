#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: integrate_ise
short_description: Resource module for Integrate Ise
description:
  - Manage operation update of the resource Integrate
    Ise. - > API to accept Cisco ISE server certificate
    for Cisco ISE server integration. Use "Cisco ISE
    Server Integration Status" Intent API to check the
    integration status. This API can be used to retry
    the failed integration.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Cisco ISE Server
      Identifier. Use 'Get Authentication and Policy
      Servers' intent API to find the identifier.
    type: str
  isCertAcceptedByUser:
    description: Value true for accept, false for deny.
      Remove this field and send empty request payload
      ( {} ) to retry the failed integration.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for System
      Settings AcceptCiscoISEServerCertificateForCiscoISEServerIntegration
    description: Complete reference of the AcceptCiscoISEServerCertificateForCiscoISEServerIntegration
      API.
    link: https://developer.cisco.com/docs/dna-center/#!accept-cisco-ise-server-certificate-for-cisco-ise-server-integration
notes:
  - SDK Method used are
    system_settings.SystemSettings.accept_cisco_ise_server_certificate_for_cisco_ise_server_integration,
  - Paths used are
    put /dna/intent/api/v1/integrate-ise/{id},
"""

EXAMPLES = r"""
---
- name: Update by id
  cisco.dnac.integrate_ise:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    id: string
    isCertAcceptedByUser: true
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "object": "string"
    }
"""
