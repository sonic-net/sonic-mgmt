#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: energy_sites_query
short_description: Resource module for Energy Sites
  Query
description:
  - Manage operation create of the resource Energy Sites
    Query. - > Submits a request to retrieve a list
    of sites along with their energy data for a specified
    time range, based on the filters provided in the
    request body. For detailed information about the
    usage of the API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-sitesEnergy-1.0.1-resolved.yaml.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  aggregateAttributes:
    description: Energy Sites Query's aggregateAttributes.
    elements: dict
    suboptions:
      function:
        description: Function.
        type: str
      name:
        description: Name.
        type: str
    type: list
  attributes:
    description: Attributes.
    elements: str
    type: list
  endTime:
    description: End Time.
    type: int
  filters:
    description: Energy Sites Query's filters.
    elements: dict
    suboptions:
      filters:
        description: Energy Sites Query's filters.
        elements: dict
        suboptions:
          key:
            description: Key.
            type: str
          operator:
            description: Operator.
            type: str
          value:
            description: Value.
            elements: str
            type: list
        type: list
      logicalOperator:
        description: Logical Operator.
        type: str
    type: list
  headers:
    description: Additional headers.
    type: dict
  page:
    description: Energy Sites Query's page.
    suboptions:
      limit:
        description: Limit.
        type: int
      offset:
        description: Offset.
        type: int
      sortBy:
        description: Energy Sites Query's sortBy.
        elements: dict
        suboptions:
          function:
            description: Function.
            type: str
          name:
            description: Name.
            type: str
          order:
            description: Order.
            type: str
        type: list
    type: dict
  startTime:
    description: Start Time.
    type: int
  taskId:
    description: TaskId query parameter. Used to retrieve
      asynchronously processed & stored data. When this
      parameter is used, the rest of the request params
      will be ignored.
    type: str
  views:
    description: Views.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sites SubmitRequestToQuerySitesEnergy
    description: Complete reference of the SubmitRequestToQuerySitesEnergy
      API.
    link: https://developer.cisco.com/docs/dna-center/#!submit-request-to-query-sites-energy
notes:
  - SDK Method used are
    sites.Sites.submit_request_to_query_sites_energy,
  - Paths used are
    post /dna/data/api/v1/energy/sites/query,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.energy_sites_query:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    aggregateAttributes:
      - function: string
        name: string
    attributes:
      - string
    endTime: 0
    filters:
      - filters:
          - key: string
            operator: string
            value:
              - string
        logicalOperator: string
    headers: '{{my_headers | from_json}}'
    page:
      limit: 0
      offset: 0
      sortBy:
        - function: string
          name: string
          order: string
    startTime: 0
    taskId: string
    views:
      - string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskLocation": "string",
        "taskId": "string"
      },
      "version": "string"
    }
"""
