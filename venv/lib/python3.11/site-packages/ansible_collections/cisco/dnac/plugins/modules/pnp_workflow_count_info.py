#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_workflow_count_info
short_description: Information module for Pnp Workflow
  Count
description:
  - Get all Pnp Workflow Count.
  - Returns the workflow count.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  name:
    description:
      - Name query parameter. Workflow Name.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) GetWorkflowCount
    description: Complete reference of the GetWorkflowCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-workflow-count
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.get_workflow_count,
  - Paths used are
    get /dna/intent/api/v1/onboarding/pnp-workflow/count,
"""

EXAMPLES = r"""
---
- name: Get all Pnp Workflow Count
  cisco.dnac.pnp_workflow_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    name: []
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": 0
    }
"""
