#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: dns_services_id_info
short_description: Information module for Dns Services
  Id
description:
  - Get Dns Services Id by id. - > Retrieves the details
    of the DNS Service matching the given id. For detailed
    information about the usage of the API, please refer
    to the Open API specification document - https //github.com/cisco-en-
    programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    DNSServices-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - >
        Id path parameter. Unique id of the DNS Service.
        It is the combination of DNS Server IP (`serverIp`)
        and Device UUID (`deviceId`) separated by underscore
        (`_`). Example If `serverIp` is `10.76.81.33`
        and `deviceId` is `6bef213c-19ca-4170-8375-b694e251101c`,
        then the `id` would be `10.76.81.33_6bef213c-19ca-4170-8375-b694e251101c`.
    type: str
  startTime:
    description:
      - >
        StartTime query parameter. Start time from which
        API queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive.
    type: float
  endTime:
    description:
      - >
        EndTime query parameter. End time to which API
        queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      RetrievesTheDetailsOfASpecificDNSServiceMatchingTheIdOfTheService
    description: Complete reference of the RetrievesTheDetailsOfASpecificDNSServiceMatchingTheIdOfTheService
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-details-of-a-specific-dns-service-matching-the-id-of-the-service
notes:
  - SDK Method used are
    devices.Devices.retrieves_the_details_of_a_specific_d_n_s_service_matching_the_id_of_the_service,
  - Paths used are
    get /dna/data/api/v1/dnsServices/{id},
"""

EXAMPLES = r"""
---
- name: Get Dns Services Id by id
  cisco.dnac.dns_services_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    startTime: 0
    endTime: 0
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
      "response": {
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
        "failures": [
          {
            "failureResponseCode": 0,
            "failureDescription": "string",
            "failedTransactions": 0
          }
        ],
        "successfulTransactions": 0,
        "latency": 0,
        "ssid": "string"
      },
      "version": "string"
    }
"""
