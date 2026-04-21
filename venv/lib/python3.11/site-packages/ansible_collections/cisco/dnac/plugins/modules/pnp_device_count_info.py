#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_device_count_info
short_description: Information module for Pnp Device
  Count
description:
  - Get all Pnp Device Count.
  - Returns the device count based on filter criteria.
    This is useful for pagination.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  serialNumber:
    description:
      - SerialNumber query parameter. Device Serial
        Number.
    elements: str
    type: list
  state_:
    description:
      - State query parameter. Device State.
    elements: str
    type: list
  onbState:
    description:
      - OnbState query parameter. Device Onboarding
        State.
    elements: str
    type: list
  name:
    description:
      - Name query parameter. Device Name.
    elements: str
    type: list
  pid:
    description:
      - Pid query parameter. Device ProductId.
    elements: str
    type: list
  source:
    description:
      - Source query parameter. Device Source.
    elements: str
    type: list
  workflowId:
    description:
      - WorkflowId query parameter. Device Workflow
        Id.
    elements: str
    type: list
  workflowName:
    description:
      - WorkflowName query parameter. Device Workflow
        Name.
    elements: str
    type: list
  smartAccountId:
    description:
      - SmartAccountId query parameter. Device Smart
        Account.
    elements: str
    type: list
  virtualAccountId:
    description:
      - VirtualAccountId query parameter. Device Virtual
        Account.
    elements: str
    type: list
  lastContact:
    description:
      - LastContact query parameter. Device Has Contacted
        lastContact > 0.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) GetDeviceCount
    description: Complete reference of the GetDeviceCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-device-count-2
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.get_device_count,
  - Paths used are
    get /dna/intent/api/v1/onboarding/pnp-device/count,
"""

EXAMPLES = r"""
---
- name: Get all Pnp Device Count
  cisco.dnac.pnp_device_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    serialNumber: []
    state_: []
    onbState: []
    name: []
    pid: []
    source: []
    workflowId: []
    workflowName: []
    smartAccountId: []
    virtualAccountId: []
    lastContact: true
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
