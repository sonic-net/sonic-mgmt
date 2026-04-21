#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_workflow
short_description: Resource module for Pnp Workflow
description:
  - Manage operations create, update and delete of the
    resource Pnp Workflow.
  - Adds a PnP Workflow along with the relevant tasks
    in the workflow into the PnP database.
  - Deletes a workflow specified by id.
  - Updates an existing workflow.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  _id:
    description: Pnp Workflow's _id.
    type: str
  addToInventory:
    description: AddToInventory flag.
    type: bool
  addedOn:
    description: Pnp Workflow's addedOn.
    type: int
  configId:
    description: Pnp Workflow's configId.
    type: str
  currTaskIdx:
    description: Pnp Workflow's currTaskIdx.
    type: int
  description:
    description: Pnp Workflow's description.
    type: str
  endTime:
    description: Pnp Workflow's endTime.
    type: int
  execTime:
    description: Pnp Workflow's execTime.
    type: int
  id:
    description: Id path parameter.
    type: str
  imageId:
    description: Pnp Workflow's imageId.
    type: str
  instanceType:
    description: Pnp Workflow's instanceType.
    type: str
  lastupdateOn:
    description: Pnp Workflow's lastupdateOn.
    type: int
  name:
    description: Pnp Workflow's name.
    type: str
  startTime:
    description: Pnp Workflow's startTime.
    type: int
  state_:
    description: Pnp Workflow's state.
    type: str
  tasks:
    description: Pnp Workflow's tasks.
    elements: dict
    suboptions:
      currWorkItemIdx:
        description: Pnp Workflow's currWorkItemIdx.
        type: int
      endTime:
        description: Pnp Workflow's endTime.
        type: int
      name:
        description: Pnp Workflow's name.
        type: str
      startTime:
        description: Pnp Workflow's startTime.
        type: int
      state:
        description: Pnp Workflow's state.
        type: str
      taskSeqNo:
        description: Pnp Workflow's taskSeqNo.
        type: int
      timeTaken:
        description: Pnp Workflow's timeTaken.
        type: int
      type:
        description: Pnp Workflow's type.
        type: str
      workItemList:
        description: Pnp Workflow's workItemList.
        elements: dict
        suboptions:
          command:
            description: Pnp Workflow's command.
            type: str
          endTime:
            description: Pnp Workflow's endTime.
            type: int
          outputStr:
            description: Pnp Workflow's outputStr.
            type: str
          startTime:
            description: Pnp Workflow's startTime.
            type: int
          state:
            description: Pnp Workflow's state.
            type: str
          timeTaken:
            description: Pnp Workflow's timeTaken.
            type: int
        type: list
    type: list
  tenantId:
    description: Pnp Workflow's tenantId.
    type: str
  type:
    description: Pnp Workflow's type.
    type: str
  useState:
    description: Pnp Workflow's useState.
    type: str
  version:
    description: Pnp Workflow's version.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) AddAWorkflow
    description: Complete reference of the AddAWorkflow
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-a-workflow
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) DeleteWorkflowById
    description: Complete reference of the DeleteWorkflowById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-workflow-by-id
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) UpdateWorkflow
    description: Complete reference of the UpdateWorkflow
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-workflow
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.add_a_workflow,
    device_onboarding_pnp.DeviceOnboardingPnp.delete_workflow_by_id,
    device_onboarding_pnp.DeviceOnboardingPnp.update_workflow,
  - Paths used are
    post /dna/intent/api/v1/onboarding/pnp-workflow,
    delete /dna/intent/api/v1/onboarding/pnp-workflow/{id},
    put /dna/intent/api/v1/onboarding/pnp-workflow/{id},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.pnp_workflow:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    _id: string
    addToInventory: true
    addedOn: 0
    configId: string
    currTaskIdx: 0
    description: string
    endTime: 0
    execTime: 0
    imageId: string
    instanceType: string
    lastupdateOn: 0
    name: string
    startTime: 0
    state_: string
    tasks:
      - currWorkItemIdx: 0
        endTime: 0
        name: string
        startTime: 0
        state: string
        taskSeqNo: 0
        timeTaken: 0
        type: string
        workItemList:
          - command: string
            endTime: 0
            outputStr: string
            startTime: 0
            state: string
            timeTaken: 0
    tenantId: string
    type: string
    useState: string
    version: 0
- name: Delete by id
  cisco.dnac.pnp_workflow:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
- name: Update by id
  cisco.dnac.pnp_workflow:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    _id: string
    addToInventory: true
    addedOn: 0
    configId: string
    currTaskIdx: 0
    description: string
    endTime: 0
    execTime: 0
    id: string
    imageId: string
    instanceType: string
    lastupdateOn: 0
    name: string
    startTime: 0
    state_: string
    tasks:
      - currWorkItemIdx: 0
        endTime: 0
        name: string
        startTime: 0
        state: string
        taskSeqNo: 0
        timeTaken: 0
        type: string
        workItemList:
          - command: string
            endTime: 0
            outputStr: string
            startTime: 0
            state: string
            timeTaken: 0
    tenantId: string
    type: string
    useState: string
    version: 0
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
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
    }
"""
