#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: site_kpi_summaries_summary_analytics
short_description: Resource module for Site Kpi Summaries
  Summary Analytics
description:
  - Manage operation create of the resource Site Kpi
    Summaries Summary Analytics. - > Submits the task
    to get summary analytics data for a given site.
    For detailed information about the usage of the
    API, please refer to the Open API specification
    document - https //github.com/cisco-en- programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    SiteKpiSummaries-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  attributes:
    description: Attributes.
    elements: str
    type: list
  endTime:
    description: End Time.
    type: int
  filters:
    description: Site Kpi Summaries Summary Analytics's
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
  startTime:
    description: Start Time.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sites SubmitRequestForSiteAnalyticsSummaryData
    description: Complete reference of the SubmitRequestForSiteAnalyticsSummaryData
      API.
    link: https://developer.cisco.com/docs/dna-center/#!submit-request-for-site-analytics-summary-data
notes:
  - SDK Method used are
    sites.Sites.submit_request_for_site_analytics_summary_data,
  - Paths used are
    post /dna/data/api/v1/siteKpiSummaries/summaryAnalytics,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.site_kpi_summaries_summary_analytics:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    attributes:
      - string
    endTime: 0
    filters:
      - key: string
        operator: string
        value: string
    startTime: 0
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
