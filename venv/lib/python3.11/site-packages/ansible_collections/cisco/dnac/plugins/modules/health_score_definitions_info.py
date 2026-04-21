#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: health_score_definitions_info
short_description: Information module for Health Score
  Definitions
description:
  - Get all Health Score Definitions.
  - Get Health Score Definitions by id.
  - Get all health score defintions. - > Get health
    score defintion for the given id. Definition includes
    all properties from HealthScoreDefinition schema
    by default. For detailed information about the usage
    of the API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-issueAndHealthDefinitions-1.0.0-resolved.yaml.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceType:
    description:
      - >
        DeviceType query parameter. These are the device
        families supported for health score definitions.
        If no input is made on device family, all device
        families are considered.
    type: str
  id:
    description:
      - >
        Id query parameter. The definition identifier.
        Examples id=015d9cba-4f53-4087-8317-7e49e5ffef46
        (single entity id request) id=015d9cba-4f53-4087-8317-7e49e5ffef46&id=015d9cba-4f53-4087-8317-7e49e5ffef47
        (multiple ids in the query param).
    type: str
  includeForOverallHealth:
    description:
      - >
        IncludeForOverallHealth query parameter. The
        inclusion status of the issue definition, either
        true or false. True indicates that particular
        health metric is included in overall health
        computation, otherwise false. By default it's
        set to true.
    type: bool
  attribute:
    description:
      - >
        Attribute query parameter. These are the attributes
        supported in health score definitions response.
        By default, all properties are sent in response.
    type: str
  offset:
    description:
      - >
        Offset query parameter. Specifies the starting
        point within all records returned by the API.
        It's one based offset. The starting value is
        1.
    type: int
  limit:
    description:
      - Limit query parameter. Maximum number of records
        to return.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetAllHealthScoreDefinitionsForGivenFilters
    description: Complete reference of the GetAllHealthScoreDefinitionsForGivenFilters
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-all-health-score-definitions-for-given-filters
  - name: Cisco DNA Center documentation for Devices
      GetHealthScoreDefinitionForTheGivenId
    description: Complete reference of the GetHealthScoreDefinitionForTheGivenId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-health-score-definition-for-the-given-id
notes:
  - SDK Method used are
    devices.Devices.get_all_health_score_definitions_for_given_filters,
    devices.Devices.get_health_score_definition_for_the_given_id,
  - Paths used are
    get /dna/intent/api/v1/healthScoreDefinitions,
    get /dna/intent/api/v1/healthScoreDefinitions/{id},
"""

EXAMPLES = r"""
---
- name: Get all Health Score Definitions
  cisco.dnac.health_score_definitions_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceType: string
    id: string
    includeForOverallHealth: true
    attribute: string
    offset: 0
    limit: 0
  register: result
- name: Get Health Score Definitions by id
  cisco.dnac.health_score_definitions_info:
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
      "response": [
        {
          "id": "string",
          "name": "string",
          "displayName": "string",
          "deviceFamily": "string",
          "description": "string",
          "includeForOverallHealth": true,
          "definitionStatus": "string",
          "thresholdValue": 0,
          "synchronizeToIssueThreshold": true,
          "lastModified": "string"
        }
      ]
    }
"""
