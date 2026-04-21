#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: icap_settings_configuration_models_id_delete_deploy
short_description: Resource module for Icap Settings
  Configuration Models Id Delete Deploy
description:
  - Manage operation create of the resource Icap Settings
    Configuration Models Id Delete Deploy. - > Creates
    a ICAP configuration intent to remove the ICAP RFSTATS
    or ANOMALY configuration from the device. The task
    has not been applied to the device yet. Subsequent
    preview-approve workflow APIs must be used to complete
    the preview-approve process. The path parameter
    'id' can be retrieved from **GET /dna/intent/api/v1/icapSettings**
    API. For detailed information about the usage of
    the API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-ICAP_APIs-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. A unique ID of the
      deployed ICAP object, which can be obtained from
      **GET /dna/intent/api/v1/icapSettings**.
    type: str
  object:
    description: Object.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sensors
      CreatesAICAPConfigurationWorkflowForICAPIntentToRemoveTheICAPConfigurationOnTheDevice
    description: Complete reference of the CreatesAICAPConfigurationWorkflowForICAPIntentToRemoveTheICAPConfigurationOnTheDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!creates-aicap-configuration-workflow-for-icap-intent-to-remove-the-icap-configuration-on-the-device
notes:
  - SDK Method used are
    sensors.Sensors.creates_ai_cap_configuration_workflow_for_i_capintent_to_remove_the_i_cap_configuration_on_the_device,
  - Paths used are
    post /dna/intent/api/v1/icapSettings/configurationModels/{id}/deleteDeploy,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.icap_settings_configuration_models_id_delete_deploy:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    id: string
    object: string
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
