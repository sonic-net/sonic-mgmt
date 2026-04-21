#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: configuration_template_deploy_v2
short_description: Resource module for Configuration
  Template Deploy V2
description:
  - Manage operation create of the resource Configuration
    Template Deploy V2.
  - V2 API to deploy a template.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  forcePushTemplate:
    description: ForcePushTemplate flag.
    type: bool
  isComposite:
    description: Composite template flag.
    type: bool
  mainTemplateId:
    description: Main template UUID of versioned template.
    type: str
  memberTemplateDeploymentInfo:
    description: MemberTemplateDeploymentInfo.
    elements: dict
    type: list
  targetInfo:
    description: Configuration Template Deploy V2's
      targetInfo.
    elements: dict
    suboptions:
      hostName:
        description: Hostname of device is required
          if targetType is MANAGED_DEVICE_HOSTNAME.
        type: str
      id:
        description: UUID of target is required if targetType
          is MANAGED_DEVICE_UUID.
        type: str
      params:
        description: Template params/values to be provisioned.
        type: dict
      resourceParams:
        description: Resource params to be provisioned.
          Refer to features page for usage details.
        elements: dict
        type: list
      type:
        description: Target type of device.
        type: str
      versionedTemplateId:
        description: Versioned templateUUID to be provisioned.
        type: str
    type: list
  templateId:
    description: UUID of template to be provisioned.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates DeployTemplateV2
    description: Complete reference of the DeployTemplateV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!deploy-template-v-2
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.deploy_template_v2,
  - Paths used are
    post /dna/intent/api/v2/template-programmer/template/deploy,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.configuration_template_deploy_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    forcePushTemplate: true
    isComposite: true
    mainTemplateId: string
    memberTemplateDeploymentInfo:
      - {}
    targetInfo:
      - hostName: string
        id: string
        params: {}
        resourceParams:
          - {}
        type: string
        versionedTemplateId: string
    templateId: string
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
