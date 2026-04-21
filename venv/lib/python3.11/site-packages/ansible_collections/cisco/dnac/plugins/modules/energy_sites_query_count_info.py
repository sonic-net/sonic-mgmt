#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: energy_sites_query_count_info
short_description: Information module for Energy Sites
  Query Count
description:
  - Get all Energy Sites Query Count. - > Gets count
    sites energy task result for the given task ID.
    For detailed information about the usage of the
    API, please refer to the Open API specification
    document - https //github.com/cisco-en- programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    sitesEnergy-1.0.1-resolved.yaml.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  taskId:
    description:
      - >
        TaskId query parameter. Used to retrieve asynchronously
        processed & stored data. When this parameter
        is used, the rest of the request params will
        be ignored.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sites CountSitesEnergyForTheGivenTaskID
    description: Complete reference of the CountSitesEnergyForTheGivenTaskID
      API.
    link: https://developer.cisco.com/docs/dna-center/#!count-sites-energy-for-the-given-task-id
notes:
  - SDK Method used are
    sites.Sites.count_sites_energy_for_the_given_task_id,
  - Paths used are
    get /dna/data/api/v1/energy/sites/query/count,
"""

EXAMPLES = r"""
---
- name: Get all Energy Sites Query Count
  cisco.dnac.energy_sites_query_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    taskId: string
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
        "count": 0
      },
      "version": "string"
    }
"""
