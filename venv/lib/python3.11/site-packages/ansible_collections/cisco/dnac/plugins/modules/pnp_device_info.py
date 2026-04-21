#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_device_info
short_description: Information module for Pnp Device
description:
  - Get all Pnp Device.
  - Get Pnp Device by id.
  - Returns device details specified by device id. -
    > Returns list of devices from Plug & Play based
    on filter criteria. Returns 50 devices by default.
    This endpoint supports Pagination and Sorting.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. The minimum and maximum
        values are 0 and 500, respectively.
    type: float
  offset:
    description:
      - >
        Offset query parameter. The first record to
        show for this page; the first record is numbered
        0. The Minimum value is 0.
    type: float
  sort:
    description:
      - Sort query parameter. Comma seperated list of
        fields to sort on.
    elements: str
    type: list
  sortOrder:
    description:
      - SortOrder query parameter. Sort Order Ascending
        (asc) or Descending (des).
    type: str
  serialNumber:
    description:
      - SerialNumber query parameter. Device Serial
        Number.
    elements: str
    type: list
  state_:
    description:
      - State query parameter. Device State.
    elements: str
    type: list
  onbState:
    description:
      - OnbState query parameter. Device Onboarding
        State.
    elements: str
    type: list
  name:
    description:
      - Name query parameter. Device Name.
    elements: str
    type: list
  pid:
    description:
      - Pid query parameter. Device ProductId.
    elements: str
    type: list
  source:
    description:
      - Source query parameter. Device Source.
    elements: str
    type: list
  workflowId:
    description:
      - WorkflowId query parameter. Device Workflow
        Id.
    elements: str
    type: list
  workflowName:
    description:
      - WorkflowName query parameter. Device Workflow
        Name.
    elements: str
    type: list
  smartAccountId:
    description:
      - SmartAccountId query parameter. Device Smart
        Account.
    elements: str
    type: list
  virtualAccountId:
    description:
      - VirtualAccountId query parameter. Device Virtual
        Account.
    elements: str
    type: list
  lastContact:
    description:
      - LastContact query parameter. Device Has Contacted
        lastContact > 0.
    type: bool
  macAddress:
    description:
      - MacAddress query parameter. Device Mac Address.
    type: str
  hostname:
    description:
      - Hostname query parameter. Device Hostname.
    type: str
  siteName:
    description:
      - SiteName query parameter. Device Site Name.
    type: str
  id:
    description:
      - Id path parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) GetDeviceById
    description: Complete reference of the GetDeviceById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-device-by-id
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) GetDeviceListSiteManagement
    description: Complete reference of the GetDeviceListSiteManagement
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-device-list-site-management
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.get_device_by_id,
    device_onboarding_pnp.DeviceOnboardingPnp.get_device_list,
  - Paths used are
    get /dna/intent/api/v1/onboarding/pnp-device,
    get /dna/intent/api/v1/onboarding/pnp-device/{id},
"""

EXAMPLES = r"""
---
- name: Get all Pnp Device
  cisco.dnac.pnp_device_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    limit: 0
    offset: 0
    sort: []
    sortOrder: string
    serialNumber: []
    state_: []
    onbState: []
    name: []
    pid: []
    source: []
    workflowId: []
    workflowName: []
    smartAccountId: []
    virtualAccountId: []
    lastContact: true
    macAddress: string
    hostname: string
    siteName: string
  register: result
- name: Get Pnp Device by id
  cisco.dnac.pnp_device_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "_id": "string",
      "deviceInfo": {
        "source": "string",
        "serialNumber": "string",
        "stack": true,
        "mode": "string",
        "state": "string",
        "location": {
          "siteId": "string",
          "address": "string",
          "latitude": "string",
          "longitude": "string",
          "altitude": "string"
        },
        "description": "string",
        "onbState": "string",
        "authenticatedMicNumber": "string",
        "authenticatedSudiSerialNo": "string",
        "capabilitiesSupported": [
          "string"
        ],
        "featuresSupported": [
          "string"
        ],
        "cmState": "string",
        "firstContact": 0,
        "lastContact": 0,
        "macAddress": "string",
        "pid": "string",
        "deviceSudiSerialNos": [
          "string"
        ],
        "lastUpdateOn": 0,
        "workflowId": "string",
        "workflowName": "string",
        "projectId": "string",
        "projectName": "string",
        "deviceType": "string",
        "agentType": "string",
        "imageVersion": "string",
        "fileSystemList": [
          {
            "type": "string",
            "writeable": true,
            "freespace": 0,
            "name": "string",
            "readable": true,
            "size": 0
          }
        ],
        "pnpProfileList": [
          {
            "profileName": "string",
            "discoveryCreated": true,
            "createdBy": "string",
            "primaryEndpoint": {
              "port": 0,
              "protocol": "string",
              "ipv4Address": {},
              "ipv6Address": {},
              "fqdn": "string",
              "certificate": "string"
            },
            "secondaryEndpoint": {
              "port": 0,
              "protocol": "string",
              "ipv4Address": {},
              "ipv6Address": {},
              "fqdn": "string",
              "certificate": "string"
            }
          }
        ],
        "imageFile": "string",
        "httpHeaders": [
          {
            "key": "string",
            "value": "string"
          }
        ],
        "neighborLinks": [
          {
            "localInterfaceName": "string",
            "localShortInterfaceName": "string",
            "localMacAddress": "string",
            "remoteInterfaceName": "string",
            "remoteShortInterfaceName": "string",
            "remoteMacAddress": "string",
            "remoteDeviceName": "string",
            "remotePlatform": "string",
            "remoteVersion": "string"
          }
        ],
        "lastSyncTime": 0,
        "ipInterfaces": [
          {
            "status": "string",
            "macAddress": "string",
            "ipv4Address": {},
            "ipv6AddressList": [
              {}
            ],
            "name": "string"
          }
        ],
        "hostname": "string",
        "authStatus": "string",
        "stackInfo": {
          "supportsStackWorkflows": true,
          "isFullRing": true,
          "stackMemberList": [
            {
              "serialNumber": "string",
              "state": "string",
              "role": "string",
              "macAddress": "string",
              "pid": "string",
              "licenseLevel": "string",
              "licenseType": "string",
              "sudiSerialNumber": "string",
              "hardwareVersion": "string",
              "stackNumber": 0,
              "softwareVersion": "string",
              "priority": 0
            }
          ],
          "stackRingProtocol": "string",
          "validLicenseLevels": [
            "string"
          ],
          "totalMemberCount": 0
        },
        "reloadRequested": true,
        "addedOn": 0,
        "siteId": "string",
        "aaaCredentials": {
          "password": "string",
          "username": "string"
        },
        "userMicNumbers": [
          "string"
        ],
        "userSudiSerialNos": [
          "string"
        ],
        "addnMacAddrs": [
          "string"
        ],
        "preWorkflowCliOuputs": [
          {
            "cli": "string",
            "cliOutput": "string"
          }
        ],
        "tags": {},
        "sudiRequired": true,
        "smartAccountId": "string",
        "virtualAccountId": "string",
        "populateInventory": true,
        "siteName": "string",
        "name": "string"
      },
      "systemResetWorkflow": {
        "_id": "string",
        "state": "string",
        "type": "string",
        "description": "string",
        "lastupdateOn": 0,
        "imageId": "string",
        "currTaskIdx": 0,
        "addedOn": 0,
        "tasks": [
          {
            "state": "string",
            "type": "string",
            "currWorkItemIdx": 0,
            "taskSeqNo": 0,
            "endTime": 0,
            "startTime": 0,
            "workItemList": [
              {
                "state": "string",
                "command": "string",
                "outputStr": "string",
                "endTime": 0,
                "startTime": 0,
                "timeTaken": 0
              }
            ],
            "timeTaken": 0,
            "name": "string"
          }
        ],
        "addToInventory": true,
        "instanceType": "string",
        "endTime": 0,
        "execTime": 0,
        "startTime": 0,
        "useState": "string",
        "configId": "string",
        "name": "string",
        "version": 0,
        "tenantId": "string"
      },
      "systemWorkflow": {
        "_id": "string",
        "state": "string",
        "type": "string",
        "description": "string",
        "lastupdateOn": 0,
        "imageId": "string",
        "currTaskIdx": 0,
        "addedOn": 0,
        "tasks": [
          {
            "state": "string",
            "type": "string",
            "currWorkItemIdx": 0,
            "taskSeqNo": 0,
            "endTime": 0,
            "startTime": 0,
            "workItemList": [
              {
                "state": "string",
                "command": "string",
                "outputStr": "string",
                "endTime": 0,
                "startTime": 0,
                "timeTaken": 0
              }
            ],
            "timeTaken": 0,
            "name": "string"
          }
        ],
        "addToInventory": true,
        "instanceType": "string",
        "endTime": 0,
        "execTime": 0,
        "startTime": 0,
        "useState": "string",
        "configId": "string",
        "name": "string",
        "version": 0,
        "tenantId": "string"
      },
      "workflow": {
        "_id": "string",
        "state": "string",
        "type": "string",
        "description": "string",
        "lastupdateOn": 0,
        "imageId": "string",
        "currTaskIdx": 0,
        "addedOn": 0,
        "tasks": [
          {
            "state": "string",
            "type": "string",
            "currWorkItemIdx": 0,
            "taskSeqNo": 0,
            "endTime": 0,
            "startTime": 0,
            "workItemList": [
              {
                "state": "string",
                "command": "string",
                "outputStr": "string",
                "endTime": 0,
                "startTime": 0,
                "timeTaken": 0
              }
            ],
            "timeTaken": 0,
            "name": "string"
          }
        ],
        "addToInventory": true,
        "instanceType": "string",
        "endTime": 0,
        "execTime": 0,
        "startTime": 0,
        "useState": "string",
        "configId": "string",
        "name": "string",
        "version": 0,
        "tenantId": "string"
      },
      "runSummaryList": [
        {
          "details": "string",
          "historyTaskInfo": {
            "type": "string",
            "workItemList": [
              {
                "state": "string",
                "command": "string",
                "outputStr": "string",
                "endTime": 0,
                "startTime": 0,
                "timeTaken": 0
              }
            ],
            "timeTaken": 0,
            "addnDetails": [
              {
                "key": "string",
                "value": "string"
              }
            ],
            "name": "string"
          },
          "errorFlag": true,
          "timestamp": 0
        }
      ],
      "workflowParameters": {
        "topOfStackSerialNumber": "string",
        "licenseLevel": "string",
        "licenseType": "string",
        "configList": [
          {
            "configParameters": [
              {
                "key": "string",
                "value": "string"
              }
            ],
            "configId": "string"
          }
        ]
      },
      "dayZeroConfig": {
        "config": "string"
      },
      "dayZeroConfigPreview": {},
      "version": 0,
      "tenantId": "string"
    }
"""
