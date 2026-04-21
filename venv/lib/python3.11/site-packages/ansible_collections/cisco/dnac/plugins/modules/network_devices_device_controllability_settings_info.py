#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_device_controllability_settings_info
short_description: Information module for Network Devices
  Device Controllability Settings
description:
  - Get all Network Devices Device Controllability Settings.
    - > Device Controllability is a system-level process
    on Catalyst Center that enforces state synchronization
    for some device-layer features. Its purpose is to
    aid in the deployment of required network settings
    that Catalyst Center needs to manage devices. Changes
    are made on network devices during discovery, when
    adding a device to Inventory, or when assigning
    a device to a site. If changes are made to any settings
    that are under the scope of this process, these
    changes are applied to the network devices during
    the Provision and Update Telemetry Settings operations,
    even if Device Controllability is disabled. The
    following device settings will be enabled as part
    of Device Controllability when devices are discovered.
    - SNMP Credentials. - NETCONF Credentials. Subsequent
    to discovery, devices will be added to Inventory.
    The following device settings will be enabled when
    devices are added to inventory. - Cisco TrustSec
    CTS Credentials. The following device settings will
    be enabled when devices are assigned to a site.
    Some of these settings can be defined at a site
    level under Design > Network Settings > Telemetry
    & Wireless. - Wired Endpoint Data Collection Enablement.
    - Controller Certificates. - SNMP Trap Server Definitions.
    - Syslog Server Definitions. - Application Visibility.
    - Application QoS Policy. - Wireless Service Assurance
    WSA. - Wireless Telemetry. - DTLS Ciphersuite. -
    AP Impersonation. If Device Controllability is disabled,
    Catalyst Center does not configure any of the preceding
    credentials or settings on devices during discovery,
    at runtime, or during site assignment. However,
    the telemetry settings and related configuration
    are pushed when the device is provisioned or when
    the update Telemetry Settings action is performed.
    Catalyst Center identifies and automatically corrects
    the following telemetry configuration issues on
    the device. - SWIM certificate issue. - IOS WLC
    NA certificate issue. - PKCS12 certificate issue.
    - IOS telemetry configuration issu.
version_added: '6.15.0'
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
  - name: Cisco DNA Center documentation for Site Design
      GetDeviceControllabilitySettings
    description: Complete reference of the GetDeviceControllabilitySettings
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-device-controllability-settings
notes:
  - SDK Method used are
    site_design.SiteDesign.get_device_controllability_settings,
  - Paths used are
    get /dna/intent/api/v1/networkDevices/deviceControllability/settings,
"""

EXAMPLES = r"""
---
- name: Get all Network Devices Device Controllability
    Settings
  cisco.dnac.network_devices_device_controllability_settings_info:
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
      "response": {
        "autocorrectTelemetryConfig": true,
        "deviceControllability": true
      },
      "version": "string"
    }
"""
