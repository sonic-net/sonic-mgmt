#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_config_info
short_description: Information module for Network Device
  Config
description:
  - Get all Network Device Config . - > Returns the
    historical device configurations running configuration
    , startup configuration , vlan if applicable by
    specified criteria.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceId:
    description:
      - >
        DeviceId query parameter. Comma separated device
        id for example cf35b0a1-407f-412f-b2f4-f0c3156695f9,aaa38191-0c22-4158-befd-779a09d7cec1.
        If device id is not provided it will fetch for
        all devices.
    type: str
  fileType:
    description:
      - FileType query parameter. Config File Type can
        be RUNNINGCONFIG or STARTUPCONFIG.
    type: str
  createdTime:
    description:
      - CreatedTime query parameter. Supported with
        logical filters GT,GTE,LT,LTE & BT time in milliseconds
        (epoc format).
    type: str
  createdBy:
    description:
      - >
        CreatedBy query parameter. Comma separated values
        for createdBy - SCHEDULED, USER, CONFIG_CHANGE_EVENT,
        SCHEDULED_FIRST_TIME, DR_CALL_BACK, PRE_DEPLOY.
    type: str
  offset:
    description:
      - Offset query parameter.
    type: float
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to be retrieved defaults to 500 if not specified,
        with a maximum allowed limit of 500.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Archive GetConfigurationArchiveDetails
    description: Complete reference of the GetConfigurationArchiveDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-configuration-archive-details
notes:
  - SDK Method used are
    configuration_archive.ConfigurationArchive.get_configuration_archive_details,
  - Paths used are
    get /dna/intent/api/v1/network-device-config,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Config
  cisco.dnac.network_device_config__info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceId: string
    fileType: string
    createdTime: string
    createdBy: string
    offset: 0
    limit: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "ipAddress": "string",
        "deviceId": "string",
        "versions": [
          {
            "files": [
              {
                "fileType": "string",
                "fileId": "string",
                "downloadPath": "string"
              }
            ],
            "createdBy": "string",
            "configChangeType": "string",
            "syslogConfigEventDto": [
              {
                "userName": "string",
                "deviceUuid": "string",
                "outOfBand": true,
                "configMethod": "string",
                "terminalName": "string",
                "loginIpAddress": "string",
                "processName": "string",
                "syslogTime": 0
              }
            ],
            "createdTime": 0,
            "startupRunningStatus": "string",
            "id": "string",
            "tags": [
              "string"
            ],
            "lastUpdatedTime": 0
          }
        ],
        "deviceName": "string"
      }
    ]
"""
