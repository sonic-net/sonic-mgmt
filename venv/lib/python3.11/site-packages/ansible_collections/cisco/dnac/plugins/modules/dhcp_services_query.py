#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: dhcp_services_query
short_description: Resource module for Dhcp Services
  Query
description:
  - Manage operation create of the resource Dhcp Services
    Query. - > Retrieves the list of DHCP Services and
    offers complex filtering and sorting capabilities.
    For detailed information about the usage of the
    API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    DHCPServices-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  endTime:
    description: End Time.
    type: int
  filters:
    description: Dhcp Services Query's filters.
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
  headers:
    description: Additional headers.
    type: dict
  page:
    description: Dhcp Services Query's page.
    suboptions:
      limit:
        description: Limit.
        type: int
      offset:
        description: Offset.
        type: int
      sortBy:
        description: Dhcp Services Query's sortBy.
        elements: dict
        suboptions:
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      RetrievesTheListOfDHCPServicesForGivenSetOfComplexFilters
    description: Complete reference of the RetrievesTheListOfDHCPServicesForGivenSetOfComplexFilters
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-list-of-dhcp-services-for-given-set-of-complex-filters
notes:
  - SDK Method used are
    devices.Devices.retrieves_the_list_of_d_h_c_p_services_for_given_set_of_complex_filters,
  - Paths used are
    post /dna/data/api/v1/dhcpServices/query,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.dhcp_services_query:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    endTime: 0
    filters:
      - key: string
        operator: string
        value:
          - string
    headers: '{{my_headers | from_json}}'
    page:
      limit: 0
      offset: 0
      sortBy:
        - name: string
          order: string
    startTime: 0
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
          "serverIp": "string",
          "deviceId": "string",
          "deviceName": "string",
          "deviceFamily": "string",
          "deviceSiteHierarchy": "string",
          "deviceSiteId": "string",
          "deviceSiteHierarchyId": "string",
          "transactions": 0,
          "failedTransactions": 0,
          "successfulTransactions": 0,
          "latency": 0,
          "discoverOfferLatency": 0,
          "requestAcknowledgeLatency": 0
        }
      ],
      "page": {
        "limit": 0,
        "offset": 0,
        "count": 0,
        "sortBy": [
          {
            "name": "string",
            "order": "string"
          }
        ]
      },
      "version": "string"
    }
"""
