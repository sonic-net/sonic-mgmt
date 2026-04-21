#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_bugs_trials_info
short_description: Information module for Network Bugs
  Trials
description:
  - Get all Network Bugs Trials.
  - Get trial details for bugs detection on network
    devices.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Compliance
      GetTrialDetailsForBugsDetectionOnNetworkDevices
    description: Complete reference of the GetTrialDetailsForBugsDetectionOnNetworkDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-trial-details-for-bugs-detection-on-network-devices
notes:
  - SDK Method used are
    compliance.Compliance.get_trial_details_for_bugs_detection_on_network_devices,
  - Paths used are
    get /dna/intent/api/v1/networkBugs/trials,
"""

EXAMPLES = r"""
---
- name: Get all Network Bugs Trials
  cisco.dnac.network_bugs_trials_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": {
        "type": "string",
        "feature": "string",
        "contractLevel": "string",
        "active": true,
        "startTime": 0,
        "endTime": 0,
        "secondsRemainingToExpiry": 0,
        "secondsSinceExpired": 0
      }
    }
"""
