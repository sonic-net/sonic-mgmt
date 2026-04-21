#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: discovery_job_info
short_description: Information module for Discovery
  Job
description:
  - Get all Discovery Job.
  - Get Discovery Job by id. - > Returns the list of
    discovery jobs for the given Discovery ID. The results
    can be optionally filtered based on IP. Discovery
    ID can be obtained using the "Get Discoveries by
    range" API.
  - Returns the list of discovery jobs for the given
    IP.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  offset:
    description:
      - Offset query parameter.
    type: int
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page. Min 1, Max 500.
    type: int
  ipAddress:
    description:
      - IpAddress query parameter.
    type: str
  name:
    description:
      - Name query parameter.
    type: str
  id:
    description:
      - Id path parameter. Discovery ID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Discovery
      GetDiscoveryJobsByIP
    description: Complete reference of the GetDiscoveryJobsByIP
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-discovery-jobs-by-ip
  - name: Cisco DNA Center documentation for Discovery
      GetListOfDiscoveriesByDiscoveryId
    description: Complete reference of the GetListOfDiscoveriesByDiscoveryId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-list-of-discoveries-by-discovery-id
notes:
  - SDK Method used are
    discovery.Discovery.get_discovery_jobs_by_ip,
    discovery.Discovery.get_list_of_discoveries_by_discovery_id,
  - Paths used are
    get /dna/intent/api/v1/discovery/job,
    get /dna/intent/api/v1/discovery/{id}/job,
"""

EXAMPLES = r"""
---
- name: Get all Discovery Job
  cisco.dnac.discovery_job_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    offset: 0
    limit: 0
    ipAddress: string
    name: string
  register: result
- name: Get Discovery Job by id
  cisco.dnac.discovery_job_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    offset: 0
    limit: 0
    ipAddress: string
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
          "attributeInfo": {},
          "cliStatus": "string",
          "discoveryStatus": "string",
          "endTime": "string",
          "httpStatus": "string",
          "id": "string",
          "inventoryCollectionStatus": "string",
          "inventoryReachabilityStatus": "string",
          "ipAddress": "string",
          "jobStatus": "string",
          "name": "string",
          "netconfStatus": "string",
          "pingStatus": "string",
          "snmpStatus": "string",
          "startTime": "string",
          "taskId": "string"
        }
      ],
      "version": "string"
    }
"""
