#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_config_files_count_info
short_description: Information module for Network Device
  Config Files Count
description:
  - Get all Network Device Config Files Count.
  - Retrieves count the details of the network device
    configuration files.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id query parameter. Unique identifier (UUID)
        of the configuration file.
    type: str
  networkDeviceId:
    description:
      - >
        NetworkDeviceId query parameter. Unique identifier
        (UUID) of the network devices. The number of
        networkDeviceId(s) must not exceed 5.
    type: str
  fileType:
    description:
      - >
        FileType query parameter. Type of device configuration
        file. Available values 'RUNNINGCONFIG', 'STARTUPCONFIG',
        'VLAN'.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Archive CountOfNetworkDeviceConfigurationFiles
    description: Complete reference of the CountOfNetworkDeviceConfigurationFiles
      API.
    link: https://developer.cisco.com/docs/dna-center/#!count-of-network-device-configuration-files
notes:
  - SDK Method used are
    configuration_archive.ConfigurationArchive.count_of_network_device_configuration_files,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceConfigFiles/count,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Config Files Count
  cisco.dnac.network_device_config_files_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
    networkDeviceId: string
    fileType: string
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
        "count": 0
      },
      "version": "string"
    }
"""
