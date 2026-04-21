#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: app_policy_intent_create
short_description: Resource module for App Policy Intent
  Create
description:
  - Manage operation create of the resource App Policy
    Intent Create.
  - Create/Update/Delete application policy.
version_added: '4.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  createList:
    description: App Policy Intent Create's createList.
    elements: dict
    suboptions:
      advancedPolicyScope:
        description: App Policy Intent Create's advancedPolicyScope.
        suboptions:
          advancedPolicyScopeElement:
            description: App Policy Intent Create's
              advancedPolicyScopeElement.
            elements: dict
            suboptions:
              groupId:
                description: The site(s) ID where the
                  Application QoS Policy will be deployed.
                elements: str
                type: list
              ssid:
                description: Ssid.
                elements: str
                type: list
            type: list
          name:
            description: Policy name.
            type: str
        type: dict
      consumer:
        description: App Policy Intent Create's consumer.
        suboptions:
          scalableGroup:
            description: App Policy Intent Create's
              scalableGroup.
            elements: dict
            suboptions:
              idRef:
                description: Id ref to application Scalable
                  group.
                type: str
            type: list
        type: dict
      contract:
        description: App Policy Intent Create's contract.
        suboptions:
          idRef:
            description: Id ref to Queueing profile.
            type: str
        type: dict
      deletePolicyStatus:
        description: NONE deployed policy to devices,
          DELETED delete policy from devices, RESTORED
          restored to original configuration.
        type: str
      exclusiveContract:
        description: App Policy Intent Create's exclusiveContract.
        suboptions:
          clause:
            description: App Policy Intent Create's
              clause.
            elements: dict
            suboptions:
              deviceRemovalBehavior:
                description: Device eemoval behavior.
                type: str
              hostTrackingEnabled:
                description: Is host tracking enabled.
                type: bool
              relevanceLevel:
                description: Relevance level.
                type: str
              type:
                description: Type.
                type: str
            type: list
        type: dict
      name:
        description: Concatination of <polcy name>_<application-set-name>
          or <polcy name>_global_policy_configuration
          or <polcy name>_queuing_customization.
        type: str
      policyScope:
        description: Policy name.
        type: str
      priority:
        description: Set to 4095 while producer refer
          to application Scalable group otherwise 100.
        type: str
      producer:
        description: App Policy Intent Create's producer.
        suboptions:
          scalableGroup:
            description: App Policy Intent Create's
              scalableGroup.
            elements: dict
            suboptions:
              idRef:
                description: Id ref to application-set
                  or application Scalable group.
                type: str
            type: list
        type: dict
    type: list
  deleteList:
    description: Delete list of Group Based Policy ids.
    elements: str
    type: list
  updateList:
    description: App Policy Intent Create's updateList.
    elements: dict
    suboptions:
      advancedPolicyScope:
        description: App Policy Intent Create's advancedPolicyScope.
        suboptions:
          advancedPolicyScopeElement:
            description: App Policy Intent Create's
              advancedPolicyScopeElement.
            elements: dict
            suboptions:
              groupId:
                description: The site(s) ID where the
                  Application QoS Policy will be deployed.
                elements: str
                type: list
              id:
                description: Id of Advance policy scope
                  element.
                type: str
              ssid:
                description: Ssid.
                elements: str
                type: list
            type: list
          id:
            description: Id of Advance policy scope.
            type: str
          name:
            description: Policy name.
            type: str
        type: dict
      consumer:
        description: App Policy Intent Create's consumer.
        suboptions:
          id:
            description: Id of Consumer.
            type: str
          scalableGroup:
            description: App Policy Intent Create's
              scalableGroup.
            elements: dict
            suboptions:
              idRef:
                description: Id ref to application Scalable
                  group.
                type: str
            type: list
        type: dict
      contract:
        description: App Policy Intent Create's contract.
        suboptions:
          idRef:
            description: Id ref to Queueing profile.
            type: str
        type: dict
      deletePolicyStatus:
        description: NONE deployed policy to devices,
          DELETED delete policy from devices, RESTORED
          restored to original configuration.
        type: str
      exclusiveContract:
        description: App Policy Intent Create's exclusiveContract.
        suboptions:
          clause:
            description: App Policy Intent Create's
              clause.
            elements: dict
            suboptions:
              deviceRemovalBehavior:
                description: Device removal behavior.
                type: str
              hostTrackingEnabled:
                description: Host tracking enabled.
                type: bool
              id:
                description: Id of Business relevance
                  or Application policy knobs clause.
                type: str
              relevanceLevel:
                description: Relevance level.
                type: str
              type:
                description: Type.
                type: str
            type: list
          id:
            description: Id of Exclusive contract.
            type: str
        type: dict
      id:
        description: Id of Group based policy.
        type: str
      name:
        description: Concatination of <polcy name>_<application-set-name>
          or <polcy name>_global_policy_configuration
          or <polcy name>_queuing_customization.
        type: str
      policyScope:
        description: Policy name.
        type: str
      priority:
        description: Set to 4095 while producer refer
          to application Scalable group otherwise 100.
        type: str
      producer:
        description: App Policy Intent Create's producer.
        suboptions:
          id:
            description: Id of Producer.
            type: str
          scalableGroup:
            description: App Policy Intent Create's
              scalableGroup.
            elements: dict
            suboptions:
              idRef:
                description: Id ref to application-set
                  or application Scalable group.
                type: str
            type: list
        type: dict
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy ApplicationPolicyIntent
    description: Complete reference of the ApplicationPolicyIntent
      API.
    link: https://developer.cisco.com/docs/dna-center/#!application-policy-intent
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.application_policy_intent,
  - Paths used are
    post /dna/intent/api/v1/app-policy-intent,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.app_policy_intent_create:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    createList:
      - advancedPolicyScope:
          advancedPolicyScopeElement:
            - groupId:
                - string
              ssid:
                - string
          name: string
        consumer:
          scalableGroup:
            - idRef: string
        contract:
          idRef: string
        deletePolicyStatus: string
        exclusiveContract:
          clause:
            - deviceRemovalBehavior: string
              hostTrackingEnabled: true
              relevanceLevel: string
              type: string
        name: string
        policyScope: string
        priority: string
        producer:
          scalableGroup:
            - idRef: string
    deleteList:
      - string
    updateList:
      - advancedPolicyScope:
          advancedPolicyScopeElement:
            - groupId:
                - string
              id: string
              ssid:
                - string
          id: string
          name: string
        consumer:
          id: string
          scalableGroup:
            - idRef: string
        contract:
          idRef: string
        deletePolicyStatus: string
        exclusiveContract:
          clause:
            - deviceRemovalBehavior: string
              hostTrackingEnabled: true
              id: string
              relevanceLevel: string
              type: string
          id: string
        id: string
        name: string
        policyScope: string
        priority: string
        producer:
          id: string
          scalableGroup:
            - idRef: string
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
