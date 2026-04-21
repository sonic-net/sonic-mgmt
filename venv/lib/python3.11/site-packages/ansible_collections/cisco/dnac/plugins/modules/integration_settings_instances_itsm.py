#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: integration_settings_instances_itsm
short_description: Resource module for Integration Settings
  Instances Itsm
description:
  - Manage operations create, update and delete of the
    resource Integration Settings Instances Itsm.
  - Creates ITSM Integration setting.
  - Deletes the ITSM Integration setting.
  - Updates the ITSM Integration setting.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  data:
    description: Integration Settings Instances Itsm's
      data.
    suboptions:
      ConnectionSettings:
        description: Integration Settings Instances
          Itsm's ConnectionSettings.
        suboptions:
          Auth_Password:
            description: Auth Password.
            type: str
          Auth_UserName:
            description: Auth User Name.
            type: str
          Url:
            description: Url.
            type: str
        type: dict
    type: dict
  description:
    description: Description of the setting instance.
    type: str
  dypName:
    description: It can be ServiceNowConnection.
    type: str
  instanceId:
    description: InstanceId path parameter. Instance
      Id of the Integration setting instance.
    type: str
  name:
    description: Name of the setting instance.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for ITSM Integration
      CreateITSMIntegrationSetting
    description: Complete reference of the CreateITSMIntegrationSetting
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-itsm-integration-setting
  - name: Cisco DNA Center documentation for ITSM Integration
      DeleteITSMIntegrationSetting
    description: Complete reference of the DeleteITSMIntegrationSetting
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-itsm-integration-setting
  - name: Cisco DNA Center documentation for ITSM Integration
      UpdateITSMIntegrationSetting
    description: Complete reference of the UpdateITSMIntegrationSetting
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-itsm-integration-setting
notes:
  - SDK Method used are
    itsm_integration.ItsmIntegration.create_itsm_integration_setting,
    itsm_integration.ItsmIntegration.delete_itsm_integration_setting,
    itsm_integration.ItsmIntegration.update_itsm_integration_setting,
  - Paths used are
    post /dna/intent/api/v1/integration-settings/instances/itsm,
    delete /dna/intent/api/v1/integration-settings/instances/itsm/{instanceId},
    put /dna/intent/api/v1/integration-settings/instances/itsm/{instanceId},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.integration_settings_instances_itsm:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    data:
      ConnectionSettings:
        Auth_Password: string
        Auth_UserName: string
        Url: string
    description: string
    dypName: string
    name: string
- name: Update by id
  cisco.dnac.integration_settings_instances_itsm:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    data:
      ConnectionSettings:
        Auth_Password: string
        Auth_UserName: string
        Url: string
    description: string
    dypName: string
    instanceId: string
    name: string
- name: Delete by id
  cisco.dnac.integration_settings_instances_itsm:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    instanceId: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "dypId": "string",
      "dypName": "string",
      "name": "string",
      "uniqueKey": "string",
      "dypMajorVersion": 0,
      "description": "string",
      "data": {
        "ConnectionSettings": {
          "Url": "string",
          "Auth_UserName": "string",
          "Auth_Password": "string"
        }
      },
      "createdDate": 0,
      "createdBy": "string",
      "updatedBy": "string",
      "softwareVersionLog": [
        {}
      ],
      "schemaVersion": 0,
      "tenantId": "string"
    }
"""
