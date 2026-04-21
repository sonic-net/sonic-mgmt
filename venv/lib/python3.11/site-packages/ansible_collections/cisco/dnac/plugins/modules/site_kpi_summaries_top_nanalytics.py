#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: site_kpi_summaries_top_nanalytics
short_description: Resource module for Site Kpi Summaries
  Top Nanalytics
description:
  - Manage operation create of the resource Site Kpi
    Summaries Top Nanalytics. - > Gets the Top N entites
    related based on site analytics for a given kpi
    type. For detailed information about the usage of
    the API, please refer to the Open API specification
    document - https //github.com/cisco-en- programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    SiteKpiSummaries-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  endTime:
    description: End Time.
    type: int
  filters:
    description: Site Kpi Summaries Top Nanalytics's
      filters.
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
        type: str
    type: list
  groupBy:
    description: Group By.
    elements: str
    type: list
  startTime:
    description: Start Time.
    type: int
  topN:
    description: Top N.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sites SubmitRequestForTopNEntitiesRelatedToSiteAnalytics
    description: Complete reference of the SubmitRequestForTopNEntitiesRelatedToSiteAnalytics
      API.
    link: https://developer.cisco.com/docs/dna-center/#!submit-request-for-top-n-entities-related-to-site-analytics
notes:
  - SDK Method used are
    sites.Sites.submit_request_for_top_n_entities_related_to_site_analytics,
  - Paths used are
    post /dna/data/api/v1/siteKpiSummaries/topNAnalytics,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.site_kpi_summaries_top_nanalytics:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    endTime: 0
    filters:
      - key: string
        operator: string
        value: string
    groupBy:
      - string
    startTime: 0
    topN: 0
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
