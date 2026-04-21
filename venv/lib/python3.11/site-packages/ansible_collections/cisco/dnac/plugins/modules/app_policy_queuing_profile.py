#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: app_policy_queuing_profile
short_description: Resource module for App Policy Queuing
  Profile
description:
  - Manage operations create, update and delete of the
    resource App Policy Queuing Profile.
  - Create new custom application queuing profile.
  - Delete existing custom application policy queuing
    profile by id.
  - Update existing custom application queuing profile.
version_added: '4.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Id of custom queuing
      profile to delete.
    type: str
  payload:
    description: App Policy Queuing Profile's payload.
    elements: dict
    suboptions:
      clause:
        description: App Policy Queuing Profile's clause.
        elements: dict
        suboptions:
          instanceId:
            description: Instance id.
            type: int
          interfaceSpeedBandwidthClauses:
            description: App Policy Queuing Profile's
              interfaceSpeedBandwidthClauses.
            elements: dict
            suboptions:
              instanceId:
                description: Instance id.
                type: int
              interfaceSpeed:
                description: Interface speed.
                type: str
              tcBandwidthSettings:
                description: App Policy Queuing Profile's
                  tcBandwidthSettings.
                elements: dict
                suboptions:
                  bandwidthPercentage:
                    description: Bandwidth percentage.
                    type: int
                  instanceId:
                    description: Instance id.
                    type: int
                  trafficClass:
                    description: Traffic Class.
                    type: str
                type: list
            type: list
          isCommonBetweenAllInterfaceSpeeds:
            description: Is common between all interface
              speeds.
            type: bool
          tcDscpSettings:
            description: App Policy Queuing Profile's
              tcDscpSettings.
            elements: dict
            suboptions:
              dscp:
                description: Dscp value.
                type: str
              instanceId:
                description: Instance id.
                type: int
              trafficClass:
                description: Traffic Class.
                type: str
            type: list
          type:
            description: The allowed clause types are
              BANDWIDTH, DSCP_CUSTOMIZATION.
            type: str
        type: list
      description:
        description: Free test description.
        type: str
      id:
        description: Id of Queueing profile.
        type: str
      name:
        description: Queueing profile name.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy CreateApplicationPolicyQueuingProfile
    description: Complete reference of the CreateApplicationPolicyQueuingProfile
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-application-policy-queuing-profile
  - name: Cisco DNA Center documentation for Application
      Policy DeleteApplicationPolicyQueuingProfile
    description: Complete reference of the DeleteApplicationPolicyQueuingProfile
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-application-policy-queuing-profile
  - name: Cisco DNA Center documentation for Application
      Policy UpdateApplicationPolicyQueuingProfile
    description: Complete reference of the UpdateApplicationPolicyQueuingProfile
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-application-policy-queuing-profile
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.create_application_policy_queuing_profile,
    application_policy.ApplicationPolicy.delete_application_policy_queuing_profile,
    application_policy.ApplicationPolicy.update_application_policy_queuing_profile,
  - Paths used are
    post /dna/intent/api/v1/app-policy-queuing-profile,
    delete /dna/intent/api/v1/app-policy-queuing-profile/{id},
    put /dna/intent/api/v1/app-policy-queuing-profile,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.app_policy_queuing_profile:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - clause:
          - instanceId: 0
            interfaceSpeedBandwidthClauses:
              - instanceId: 0
                interfaceSpeed: string
                tcBandwidthSettings:
                  - bandwidthPercentage: 0
                    instanceId: 0
                    trafficClass: string
            isCommonBetweenAllInterfaceSpeeds: true
            tcDscpSettings:
              - dscp: string
                instanceId: 0
                trafficClass: string
            type: string
        description: string
        id: string
        name: string
- name: Create
  cisco.dnac.app_policy_queuing_profile:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - clause:
          - interfaceSpeedBandwidthClauses:
              - interfaceSpeed: string
                tcBandwidthSettings:
                  - bandwidthPercentage: 0
                    trafficClass: string
            isCommonBetweenAllInterfaceSpeeds: true
            tcDscpSettings:
              - dscp: string
                trafficClass: string
            type: string
        description: string
        name: string
- name: Delete by id
  cisco.dnac.app_policy_queuing_profile:
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
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
