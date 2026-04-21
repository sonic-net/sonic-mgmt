#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_config_files_id_download_unmasked
short_description: Resource module for Network Device
  Config Files Id Download Unmasked
description:
  - Manage operation create of the resource Network
    Device Config Files Id Download Unmasked.
  - Download the unmasked raw device configuration by
    providing the file `id`.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. The value of `id`
      can be obtained from the response of API `/dna/intent/api/v1/networkDeviceConfigFiles`.
    type: str
  password:
    description: Password for the zip file to protect
      exported configurations. Must contain, at minimum
      8 characters, one lowercase letter, one uppercase
      letter, one number, one special character(-=;,./~!@#$%^&*()_+{}|
      ?). It may not contain white space or the characters
      <>.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Archive DownloadUnmaskedrawDeviceConfigurationAsZIP
    description: Complete reference of the DownloadUnmaskedrawDeviceConfigurationAsZIP
      API.
    link: https://developer.cisco.com/docs/dna-center/#!download-unmaskedraw-device-configuration-as-zip
notes:
  - SDK Method used are
    configuration_archive.ConfigurationArchive.download_unmaskedraw_device_configuration_as_zip,
  - Paths used are
    post /dna/intent/api/v1/networkDeviceConfigFiles/{id}/downloadUnmasked,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_device_config_files_id_download_unmasked:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    id: string
    password: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
