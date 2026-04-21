#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: site_health_summaries_summary_analytics
short_description: Resource module for Site Health Summaries
  Summary Analytics
description:
  - Manage operation create of the resource Site Health
    Summaries Summary Analytics. - > Query an aggregated
    summary of all site health This API provides the
    latest health data from a given `endTime` If data
    is not ready for the provided endTime, the request
    will fail, and the error message will indicate the
    recommended endTime to use to retrieve a complete
    data set. This behavior may occur if the provided
    endTime=currentTime, since we are not a real time
    system. When `endTime` is not provided, the API
    returns the latest data. This API also provides
    issue data. The `startTime` query param can be used
    to specify the beginning point of time range to
    retrieve the active issue counts in. When this param
    is not provided, the default `startTime` will be
    24 hours before endTime.
version_added: '6.15.0'
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
  id:
    description: Id query parameter. The list of entity
      Uuids. (Ex."6bef213c-19ca-4170-8375-b694e251101c")
      Examples id=6bef213c-19ca-4170-8375-b694e251101c
      (single entity uuid requested) id=6bef213c-19ca-4170-8375-b694e251101c&id=32219612-819e-4b5e-a96b-cf22aca13dd9&id=2541e9a7-b80d-4955-8aa2-79...
      (multiple entity uuid with '&' separator).
    type: str
  siteHierarchy:
    description: SiteHierarchy query parameter. The
      full hierarchical breakdown of the site tree starting
      from Global site name and ending with the specific
      site name. The Root site is named "Global" (Ex.
      `Global/AreaName/BuildingName/FloorName`) This
      field supports wildcard asterisk (`*`) character
      search support. E.g. `*/San*, */San, /San*` Examples
      `?siteHierarchy=Global/AreaName/BuildingName/FloorName`
      (single siteHierarchy requested) `?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Global/...
      (multiple siteHierarchies requested).
    type: str
  siteHierarchyId:
    description: SiteHierarchyId query parameter. The
      full hierarchy breakdown of the site tree in id
      form starting from Global site UUID and ending
      with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)
      This field supports wildcard asterisk (`*`) character
      search support. E.g. `*uuid*, *uuid, uuid*` Examples
      `?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid
      `(single siteHierarchyId requested) `?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globa...
      (multiple siteHierarchyIds requested).
    type: str
  siteType:
    description: SiteType query parameter. The type
      of the site. A site can be an area, building,
      or floor. Default when not provided will be `floor,building,area`
      Examples `?siteType=area` (single siteType requested)
      `?siteType=area&siteType=building&siteType=floor`
      (multiple siteTypes requested).
    type: str
  startTime:
    description: Start Time.
    type: int
  views:
    description: Views.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sites QueryAnAggregatedSummaryOfSiteHealthData
    description: Complete reference of the QueryAnAggregatedSummaryOfSiteHealthData
      API.
    link: https://developer.cisco.com/docs/dna-center/#!query-an-aggregated-summary-of-site-health-data
notes:
  - SDK Method used are
    sites.Sites.query_an_aggregated_summary_of_site_health_data,
  - Paths used are
    post /dna/data/api/v1/siteHealthSummaries/summaryAnalytics,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.site_health_summaries_summary_analytics:
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
    id: string
    siteHierarchy: string
    siteHierarchyId: string
    siteType: string
    startTime: 0
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
        "id": "string",
        "siteHierarchy": "string",
        "siteHierarchyId": "string",
        "siteType": "string",
        "latitude": 0,
        "longitude": 0,
        "networkDeviceGoodHealthPercentage": 0,
        "networkDeviceGoodHealthCount": 0,
        "clientGoodHealthCount": 0,
        "clientGoodHealthPercentage": 0,
        "wiredClientGoodHealthPercentage": 0,
        "wirelessClientGoodHealthPercentage": 0,
        "clientCount": 0,
        "wiredClientCount": 0,
        "wirelessClientCount": 0,
        "wiredClientGoodHealthCount": 0,
        "wirelessClientGoodHealthCount": 0,
        "networkDeviceCount": 0,
        "accessDeviceCount": 0,
        "accessDeviceGoodHealthCount": 0,
        "coreDeviceCount": 0,
        "coreDeviceGoodHealthCount": 0,
        "distributionDeviceCount": 0,
        "distributionDeviceGoodHealthCount": 0,
        "routerDeviceCount": 0,
        "routerDeviceGoodHealthCount": 0,
        "wirelessDeviceCount": 0,
        "wirelessDeviceGoodHealthCount": 0,
        "apDeviceCount": 0,
        "apDeviceGoodHealthCount": 0,
        "wlcDeviceCount": 0,
        "wlcDeviceGoodHealthCount": 0,
        "switchDeviceCount": 0,
        "switchDeviceGoodHealthCount": 0,
        "accessDeviceGoodHealthPercentage": 0,
        "coreDeviceGoodHealthPercentage": 0,
        "distributionDeviceGoodHealthPercentage": 0,
        "routerDeviceGoodHealthPercentage": 0,
        "apDeviceGoodHealthPercentage": 0,
        "wlcDeviceGoodHealthPercentage": 0,
        "switchDeviceGoodHealthPercentage": 0,
        "wirelessDeviceGoodHealthPercentage": 0,
        "clientDataUsage": 0,
        "p1IssueCount": 0,
        "p2IssueCount": 0,
        "p3IssueCount": 0,
        "p4IssueCount": 0,
        "issueCount": 0
      },
      "version": "string"
    }
"""
