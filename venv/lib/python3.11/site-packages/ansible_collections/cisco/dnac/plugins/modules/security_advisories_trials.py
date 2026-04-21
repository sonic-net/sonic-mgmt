#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_advisories_trials
short_description: Resource module for Security Advisories
  Trials
description:
  - Manage operation create of the resource Security
    Advisories Trials.
  - Creates a trial for security advisories detection
    on network devices. The.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options: {}
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Compliance
      CreatesATrialForSecurityAdvisoriesDetectionOnNetworkDevices
    description: Complete reference of the CreatesATrialForSecurityAdvisoriesDetectionOnNetworkDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!creates-a-trial-for-security-advisories-detection-on-network-devices
notes:
  - SDK Method used are
    compliance.Compliance.creates_a_trial_for_security_advisories_detection_on_network_devices,
  - Paths used are
    post /dna/intent/api/v1/securityAdvisories/trials,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.security_advisories_trials:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
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
        "url": "string",
        "taskId": "string"
      }
    }
"""
