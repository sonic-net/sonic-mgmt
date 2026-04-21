#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_issues_remediation_provision
short_description: Resource module for Network Devices
  Issues Remediation Provision
description:
  - Manage operation create of the resource Network
    Devices Issues Remediation Provision. - > Remediates
    configuration compliance issues. Compliance issues
    related to 'Routing', 'HA Remediation', 'Software
    Image', 'Securities Advisories', 'SD-Access Unsupported
    Configuration', 'Workflow', etc. Will not be addressed
    by this API.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Network device identifier.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Compliance
      ComplianceRemediation
    description: Complete reference of the ComplianceRemediation
      API.
    link: https://developer.cisco.com/docs/dna-center/#!compliance-remediation
notes:
  - SDK Method used are
    compliance.Compliance.compliance_remediation,
  - Paths used are
    post /dna/intent/api/v1/compliance/networkDevices/{id}/issues/remediation/provision,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_devices_issues_remediation_provision:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
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
