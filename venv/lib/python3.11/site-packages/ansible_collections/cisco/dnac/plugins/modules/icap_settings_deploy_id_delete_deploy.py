#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: icap_settings_deploy_id_delete_deploy
short_description: Resource module for Icap Settings
  Deploy Id Delete Deploy
description:
  - Manage operation create of the resource Icap Settings
    Deploy Id Delete Deploy. - > Remove the ICAP configuration
    from the device by *id* without preview-deploy.
    The path parameter *id* can be retrieved from the
    **GET /dna/intent/api/v1/icapSettings** API. The
    response body contains a task object with a taskId
    and a URL. Use the URL to check the task status.
    ICAP FULL, ONBOARDING, OTA, and SPECTRUM configurations
    have a durationInMins field. A disable task is scheduled
    to remove the configuration from the device. Removing
    the ICAP intent should be done after the pre-scheduled
    disable task has been deployed. For detailed information
    about the usage of the API, please refer to the
    Open API specification document - https //github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    ICAP_APIs-1.0.0-resolved.yaml.
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
      RemoveTheICAPConfigurationOnTheDeviceWithoutPreview
    description: Complete reference of the RemoveTheICAPConfigurationOnTheDeviceWithoutPreview
      API.
    link: https://developer.cisco.com/docs/dna-center/#!remove-the-icap-configuration-on-the-device-without-preview
notes:
  - SDK Method used are
    sensors.Sensors.remove_the_i_cap_configuration_on_the_device_without_preview,
  - Paths used are
    post /dna/intent/api/v1/icapSettings/deploy/{id}/deleteDeploy,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.icap_settings_deploy_id_delete_deploy:
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
