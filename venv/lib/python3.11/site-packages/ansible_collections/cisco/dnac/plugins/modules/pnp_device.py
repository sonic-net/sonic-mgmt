#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_device
short_description: Resource module for Pnp Device
description:
  - Manage operations create, update and delete of the
    resource Pnp Device.
  - Adds a device to the PnP database.
  - Deletes specified device from PnP database.
  - Updates device details specified by device id in
    PnP database.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deviceInfo:
    description: Pnp Device's deviceInfo.
    suboptions:
      description:
        description: Description.
        type: str
      deviceSudiSerialNos:
        description: Device Sudi Serial Nos.
        elements: str
        type: list
      hostname:
        description: Hostname.
        type: str
      macAddress:
        description: Mac Address.
        type: str
      pid:
        description: Pid.
        type: str
      serialNumber:
        description: Serial Number.
        type: str
      siteId:
        description: Site Id.
        type: str
      stack:
        description: Stack.
        type: bool
      stackInfo:
        description: Pnp Device's stackInfo.
        suboptions:
          isFullRing:
            description: Is Full Ring.
            type: bool
          stackMemberList:
            description: Pnp Device's stackMemberList.
            elements: dict
            suboptions:
              hardwareVersion:
                description: Hardware Version.
                type: str
              licenseLevel:
                description: License Level.
                type: str
              licenseType:
                description: License Type.
                type: str
              macAddress:
                description: Mac Address.
                type: str
              pid:
                description: Pid.
                type: str
              priority:
                description: Priority.
                type: float
              role:
                description: Role.
                type: str
              serialNumber:
                description: Serial Number.
                type: str
              softwareVersion:
                description: Software Version.
                type: str
              stackNumber:
                description: Stack Number.
                type: float
              state:
                description: State.
                type: str
              sudiSerialNumber:
                description: Sudi Serial Number.
                type: str
            type: list
          stackRingProtocol:
            description: Stack Ring Protocol.
            type: str
          supportsStackWorkflows:
            description: Supports Stack Workflows.
            type: bool
          totalMemberCount:
            description: Total Member Count.
            type: float
          validLicenseLevels:
            description: Valid License Levels.
            elements: str
            type: list
        type: dict
      sudiRequired:
        description: Is Sudi Required.
        type: bool
      userMicNumbers:
        description: User Mic Numbers.
        elements: str
        type: list
      userSudiSerialNos:
        description: List of Secure Unique Device Identifier
          (SUDI) serial numbers to perform SUDI authorization,
          Required if sudiRequired is true.
        elements: str
        type: list
      workflowId:
        description: Workflow Id.
        type: str
      workflowName:
        description: Workflow Name.
        type: str
    type: dict
  id:
    description: Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) AddDevice
    description: Complete reference of the AddDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-device-2
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) DeleteDeviceByIdFromPnP
    description: Complete reference of the DeleteDeviceByIdFromPnP
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-device-by-id-from-pn-p
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) UpdateDevice
    description: Complete reference of the UpdateDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-device
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.add_device,
    device_onboarding_pnp.DeviceOnboardingPnp.delete_device_by_id_from_pnp,
    device_onboarding_pnp.DeviceOnboardingPnp.update_device,
  - Paths used are
    post /dna/intent/api/v1/onboarding/pnp-device,
    delete /dna/intent/api/v1/onboarding/pnp-device/{id},
    put /dna/intent/api/v1/onboarding/pnp-device/{id},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.pnp_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    deviceInfo:
      description: string
      deviceSudiSerialNos:
        - string
      hostname: string
      macAddress: string
      pid: string
      serialNumber: string
      siteId: string
      stack: true
      stackInfo:
        isFullRing: true
        stackMemberList:
          - hardwareVersion: string
            licenseLevel: string
            licenseType: string
            macAddress: string
            pid: string
            priority: 0
            role: string
            serialNumber: string
            softwareVersion: string
            stackNumber: 0
            state: string
            sudiSerialNumber: string
        stackRingProtocol: string
        supportsStackWorkflows: true
        totalMemberCount: 0
        validLicenseLevels:
          - string
      sudiRequired: true
      userMicNumbers:
        - string
      userSudiSerialNos:
        - string
      workflowId: string
      workflowName: string
- name: Update by id
  cisco.dnac.pnp_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    deviceInfo:
      hostname: string
      pid: string
      serialNumber: string
      stack: true
      sudiRequired: true
      userSudiSerialNos:
        - string
    id: string
- name: Delete by id
  cisco.dnac.pnp_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
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
