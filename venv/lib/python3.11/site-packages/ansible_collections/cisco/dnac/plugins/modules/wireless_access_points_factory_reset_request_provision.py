#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_access_points_factory_reset_request_provision
short_description: Resource module for Wireless Access
  Points Factory Reset Request Provision
description:
  - Manage operation create of the resource Wireless
    Access Points Factory Reset Request Provision. -
    > This API is used to factory reset Access Points.
    It is supported for maximum 100 Access Points per
    request. Factory reset clears all configurations
    from the Access Points. After factory reset the
    Access Point may become unreachable from the currently
    associated Wireless Controller and may or may not
    join back the same controller.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  apMacAddresses:
    description: List of Access Point's Ethernet MAC
      addresses, set maximum 100 ethernet MAC addresses
      per request.
    elements: str
    type: list
  keepStaticIPConfig:
    description: Set the value of keepStaticIPConfig
      to false, to clear all configurations from Access
      Points and set the value of keepStaticIPConfig
      to true, to clear all configurations from Access
      Points without clearing static IP configuration.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      FactoryResetAccessPoints
    description: Complete reference of the FactoryResetAccessPoints
      API.
    link: https://developer.cisco.com/docs/dna-center/#!factory-reset-access-points
notes:
  - SDK Method used are
    wireless.Wireless.factory_reset_access_points,
  - Paths used are
    post /dna/intent/api/v1/wirelessAccessPoints/factoryResetRequest/provision,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wireless_access_points_factory_reset_request_provision:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    apMacAddresses:
      - string
    keepStaticIPConfig: true
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
