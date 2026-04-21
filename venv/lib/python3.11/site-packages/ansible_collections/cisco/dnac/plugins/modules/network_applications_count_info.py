#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_applications_count_info
short_description: Information module for Network Applications
  Count
description:
  - Get all Network Applications Count. - > Retrieves
    the number of network applications by applying basic
    filtering. If startTime and endTime are not provided,
    the API defaults to the last 24 hours. `siteId`
    is mandatory. `siteId` must be a site UUID of a
    building. For detailed information about the usage
    of the API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-NetworkApplications-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
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
  siteId:
    description:
      - >
        SiteId query parameter. The site UUID without
        the top level hierarchy. `siteId` is mandatory.
        `siteId` must be a site UUID of a building.
        (Ex."buildingUuid") Examples `siteId=buildingUuid`
        (single siteId requested) `siteId=buildingUuid1&siteId=buildingUuid2`
        (multiple siteId requested).
    type: str
  ssid:
    description:
      - >
        Ssid query parameter. In the context of a network
        application, SSID refers to the name of the
        wireless network to which the client connects.
        Examples `ssid=Alpha` (single ssid requested)
        `ssid=Alpha&ssid=Guest` (multiple ssid requested).
    type: str
  applicationName:
    description:
      - >
        ApplicationName query parameter. Name of the
        application for which the experience data is
        intended. Examples `applicationName=webex` (single
        applicationName requested) `applicationName=webex&applicationName=teams`
        (multiple applicationName requested).
    type: str
  businessRelevance:
    description:
      - >
        BusinessRelevance query parameter. The application
        can be chosen to be categorized as business-relevant,
        irrelevant, or default (neutral). By doing so,
        the assurance application prioritizes the monitoring
        and analysis of business-relevant data, ensuring
        critical insights are captured. Applications
        marked as irrelevant or default are selectively
        excluded from certain data sets, streamlining
        focus on what's most important for business
        outcomes.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Applications
      RetrievesTheTotalCountOfNetworkApplicationsByApplyingBasicFiltering
    description: Complete reference of the RetrievesTheTotalCountOfNetworkApplicationsByApplyingBasicFiltering
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-total-count-of-network-applications-by-applying-basic-filtering
notes:
  - SDK Method used are
    applications.Applications.retrieves_the_total_count_of_network_applications_by_applying_basic_filtering,
  - Paths used are
    get /dna/data/api/v1/networkApplications/count,
"""

EXAMPLES = r"""
---
- name: Get all Network Applications Count
  cisco.dnac.network_applications_count_info:
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
    siteId: string
    ssid: string
    applicationName: string
    businessRelevance: string
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
