#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: application_visibility_network_devices_disable_app_telemetry
short_description: Resource module for Application Visibility
  Network Devices Disable App Telemetry
description:
  - Manage operation create of the resource Application
    Visibility Network Devices Disable App Telemetry.
    - > This API can be used to disable application
    telemetry feature on multiple network devices. Request
    payload should include the list of network devices
    where it has to be disabled.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  networkDeviceIds:
    description: List of network device ids where Application
      Telemetry has to be disabled.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy DisableApplicationTelemetryFeatureOnMultipleNetworkDevices
    description: Complete reference of the DisableApplicationTelemetryFeatureOnMultipleNetworkDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!disable-application-telemetry-feature-on-multiple-network-devices
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.disable_application_telemetry_feature_on_multiple_network_devices,
  - Paths used are
    post /dna/intent/api/v1/applicationVisibility/networkDevices/disableAppTelemetry,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.application_visibility_network_devices_disable_app_telemetry:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    networkDeviceIds:
      - string
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
