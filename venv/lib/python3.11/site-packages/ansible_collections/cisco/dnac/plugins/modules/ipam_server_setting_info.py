#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ipam_server_setting_info
short_description: Information module for Ipam Server
  Setting
description:
  - Get all Ipam Server Setting. - > Retrieves configuration
    details of the external IPAM server. If an external
    IPAM server has not been created, this resource
    will return a `404` response.
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
  - name: Cisco DNA Center documentation for System
      Settings RetrievesConfigurationDetailsOfTheExternalIPAMServer
    description: Complete reference of the RetrievesConfigurationDetailsOfTheExternalIPAMServer
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-configuration-details-of-the-external-ipam-server
notes:
  - SDK Method used are
    system_settings.SystemSettings.retrieves_configuration_details_of_the_external_ip_a_m_server,
  - Paths used are
    get /dna/intent/api/v1/ipam/serverSetting,
"""

EXAMPLES = r"""
---
- name: Get all Ipam Server Setting
  cisco.dnac.ipam_server_setting_info:
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
        "provider": "string",
        "serverName": "string",
        "serverUrl": "string",
        "state": "string",
        "userName": "string",
        "view": "string"
      },
      "version": "string"
    }
"""
