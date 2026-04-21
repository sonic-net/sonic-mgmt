#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: images_distribution_server_settings
short_description: Resource module for Images Distribution
  Server Settings
description:
  - Manage operations create, update and delete of the
    resource Images Distribution Server Settings.
  - Add remote server for distributing software images.
    Upto two such distribution servers are supported.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  password:
    description: Server password.
    type: str
  portNumber:
    description: Port number.
    type: float
  rootLocation:
    description: Server root location.
    type: str
  serverAddress:
    description: FQDN or IP address of the server.
    type: str
  username:
    description: Server username.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) AddImageDistributionServer
    description: Complete reference of the AddImageDistributionServer
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-image-distribution-server
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.add_image_distribution_server,
  - Paths used are
    post /dna/intent/api/v1/images/distributionServerSettings,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.images_distribution_server_settings:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    password: string
    portNumber: 0
    rootLocation: string
    serverAddress: string
    username: string
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
