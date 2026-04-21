#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: virtual_network_health_summaries_info
short_description: Information module for Virtual Network
  Health Summaries
description:
  - Get all Virtual Network Health Summaries. - > Get
    a paginated list of Virtual Networks with health
    summary. Layer 2 Virtual Networks are only included
    in health reporting for EVPN protocol deployments.
    The special Layer 3 VN called "INFRA_VN" is also
    not included for user access through Assurance virtualNetworkHealthSummaries
    APIS. Please find INFRA_VN related health metrics
    under /data/api/v1/fabricSiteHealthSummaries Ex
    attributes "pubsubInfraVnGoodHealthPercentage" and
    "bgpPeerInfraVnScoreGoodHealthPercentage" .
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
  limit:
    description:
      - Limit query parameter. Maximum number of records
        to return.
    type: float
  offset:
    description:
      - >
        Offset query parameter. Specifies the starting
        point within all records returned by the API.
        It's one based offset. The starting value is
        1.
    type: float
  sortBy:
    description:
      - SortBy query parameter. A field within the response
        to sort by.
    type: str
  order:
    description:
      - Order query parameter. The sort order of the
        field ascending or descending.
    type: str
  id:
    description:
      - >
        Id query parameter. The list of entity Uuids.
        (Ex."6bef213c-19ca-4170-8375-b694e251101c")
        Examples id=6bef213c-19ca-4170-8375-b694e251101c
        (single entity uuid requested) id=6bef213c-19ca-4170-8375-
        b694e251101c&id=32219612-819e-4b5e-a96b-cf22aca13dd9&id=2541e9a7-b80d-4955-8aa2-79b233318ba0
        (multiple entity uuid with '&' separator).
    type: str
  vnLayer:
    description:
      - VnLayer query parameter. VN Layer information
        covering Layer 3 or Layer 2 VNs.
    type: str
  attribute:
    description:
      - Attribute query parameter. The interested fields
        in the request. For valid attributes, verify
        the documentation.
    type: str
  view:
    description:
      - >
        View query parameter. The specific summary view
        being requested. This is an optional parameter
        which can be passed to get one or more of the
        specific health data summaries associated with
        virtual networks.
    type: str
  siteHierarchy:
    description:
      - >
        SiteHierarchy query parameter. The full hierarchical
        breakdown of the site tree starting from Global
        site name and ending with the specific site
        name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)
        This field supports wildcard asterisk (`*`)
        character search support. E.g. `*/San*, */San,
        /San*` Examples `?siteHierarchy=Global/AreaName/BuildingName/FloorName`
        (single siteHierarchy requested) `?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Gl
        obal/AreaName2/BuildingName2/FloorName2` (multiple
        siteHierarchies requested).
    type: str
  SiteHierarchyId:
    description:
      - >
        SiteHierarchyId query parameter. The full hierarchy
        breakdown of the site tree in id form starting
        from Global site UUID and ending with the specific
        site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)
        This field supports wildcard asterisk (`*`)
        character search support. E.g. `*uuid*, *uuid,
        uuid*` Examples `?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid
        `(single siteHierarchyId requested) `?siteH
        ierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2
        /floorUuid2` (multiple siteHierarchyIds requested).
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA ReadListOfVirtualNetworksWithTheirHealthSummary
    description: Complete reference of the ReadListOfVirtualNetworksWithTheirHealthSummary
      API.
    link: https://developer.cisco.com/docs/dna-center/#!read-list-of-virtual-networks-with-their-health-summary
notes:
  - SDK Method used are
    sda.Sda.read_list_of_virtual_networks_with_their_health_summary,
  - Paths used are
    get /dna/data/api/v1/virtualNetworkHealthSummaries,
"""

EXAMPLES = r"""
---
- name: Get all Virtual Network Health Summaries
  cisco.dnac.virtual_network_health_summaries_info:
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
    limit: 0
    offset: 0
    sortBy: string
    order: string
    id: string
    vnLayer: string
    attribute: string
    view: string
    siteHierarchy: string
    SiteHierarchyId: string
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
          "vlan": "string",
          "vnid": "string",
          "layer": "string",
          "associatedL3Vn": "string",
          "totalEndpoints": 0,
          "totalFabricSites": 0,
          "goodHealthPercentage": 0,
          "goodHealthDeviceCount": 0,
          "totalHealthDeviceCount": 0,
          "fairHealthDeviceCount": 0,
          "poorHealthDeviceCount": 0,
          "noHealthDeviceCount": 0,
          "vnFabricControlPlaneGoodHealthPercentage": 0,
          "vnFabricControlPlaneTotalDeviceCount": 0,
          "vnFabricControlPlaneGoodHealthDeviceCount": 0,
          "vnFabricControlPlanePoorHealthDeviceCount": 0,
          "vnFabricControlPlaneFairHealthDeviceCount": 0,
          "vnFabricControlPlaneNoHealthDeviceCount": 0,
          "vnServicesHealthPercentage": 0,
          "vnServicesTotalDeviceCount": 0,
          "vnServicesGoodHealthDeviceCount": 0,
          "vnServicesPoorHealthDeviceCount": 0,
          "vnServicesFairHealthDeviceCount": 0,
          "vnServicesNoHealthDeviceCount": 0,
          "vnExitHealthPercentage": 0,
          "vnExitTotalDeviceCount": 0,
          "vnExitGoodHealthDeviceCount": 0,
          "vnExitPoorHealthDeviceCount": 0,
          "vnExitFairHealthDeviceCount": 0,
          "vnExitNoHealthDeviceCount": 0,
          "vnStatusHealthPercentage": 0,
          "vnStatusTotalDeviceCount": 0,
          "vnStatusGoodHealthDeviceCount": 0,
          "vnStatusPoorHealthDeviceCount": 0,
          "vnStatusFairHealthDeviceCount": 0,
          "vnStatusNoHealthDeviceCount": 0,
          "pubsubSessionGoodHealthPercentage": 0,
          "pubsubSessionTotalDeviceCount": 0,
          "pubsubSessionGoodHealthDeviceCount": 0,
          "pubsubSessionPoorHealthDeviceCount": 0,
          "pubsubSessionFairHealthDeviceCount": 0,
          "pubsubSessionNoHealthDeviceCount": 0,
          "multiCastGoodHealthPercentage": 0,
          "multiCastTotalDeviceCount": 0,
          "multiCastGoodHealthDeviceCount": 0,
          "multiCastPoorHealthDeviceCount": 0,
          "multiCastFairHealthDeviceCount": 0,
          "internetAvailGoodHealthPercentage": 0,
          "internetAvailTotalDeviceCount": 0,
          "internetAvailGoodHealthDeviceCount": 0,
          "internetAvailPoorHealthDeviceCount": 0,
          "internetAvailFairHealthDeviceCount": 0,
          "internetAvailNoHealthDeviceCount": 0,
          "bgpPeerGoodHealthPercentage": 0,
          "bgpPeerTotalDeviceCount": 0,
          "bgpPeerGoodHealthDeviceCount": 0,
          "bgpPeerPoorHealthDeviceCount": 0,
          "bgpPeerFairHealthDeviceCount": 0,
          "bgpPeerNoHealthDeviceCount": 0,
          "vniGoodHealthPercentage": 0,
          "vniTotalDeviceCount": 0,
          "vniGoodHealthDeviceCount": 0,
          "vniPoorHealthDeviceCount": 0,
          "vniFairHealthDeviceCount": 0,
          "vniNoHealthDeviceCount": 0,
          "networkProtocol": "string"
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
