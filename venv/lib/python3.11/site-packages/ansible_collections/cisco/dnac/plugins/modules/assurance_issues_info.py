#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: assurance_issues_info
short_description: Information module for Assurance
  Issues
description:
  - Get all Assurance Issues.
  - Get Assurance Issues by id. - > Returns all details
    of each issue along with suggested actions for given
    set of filters specified in query parameters. If
    there is no start and/or end time, then end time
    will be defaulted to current time and start time
    will be defaulted to 24-hours ago from end time.
    All string type query parameters support wildcard
    search using *. For example siteHierarchy=Global/San
    Jose/* returns issues under all sites whole siteHierarchy
    starts with "Global/San Jose/". Https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesList-1.0.0-resolved.yaml.
    - > Returns all the details and suggested actions
    of an issue for the given issue id. Https //github.com/cisco-en-
    programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    IssuesList-1.0.0-resolved.yaml.
version_added: '6.15.0'
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
        Value is inclusive. If `startTime` is not provided,
        API will default to current time.
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
      - Limit query parameter. Maximum number of issues
        to return.
    type: int
  offset:
    description:
      - >
        Offset query parameter. Specifies the starting
        point within all records returned by the API.
        It's one based offset. The starting value is
        1.
    type: int
  sortBy:
    description:
      - SortBy query parameter.
    type: str
  order:
    description:
      - Order query parameter. The sort order of the
        field ascending or descending.
    type: str
  isGlobal:
    description:
      - >
        IsGlobal query parameter. Global issues are
        those issues which impacts across many devices,
        sites. They are also displayed on Issue Dashboard
        in Catalyst Center UI. Non-Global issues are
        displayed only on Client 360 or Device 360 pages.
        If this flag is 'true', only global issues are
        returned. If it if 'false', all issues are returned.
    type: bool
  priority:
    description:
      - >
        Priority query parameter. Priority of the issue.
        Supports single priority and multiple priorities
        Examples priority=P1 (single priority requested)
        priority=P1&priority=P2&priority=P3 (multiple
        priorities requested).
    type: str
  severity:
    description:
      - >
        Severity query parameter. Severity of the issue.
        Supports single severity and multiple severities.
        Examples severity=high (single severity requested)
        severity=high&severity=medium (multiple severities
        requested).
    type: str
  status:
    description:
      - >
        Status query parameter. Status of the issue.
        Supports single status and multiple statuses.
        Examples status=active (single status requested)
        status=active&status=resolved (multiple statuses
        requested).
    type: str
  entityType:
    description:
      - >
        EntityType query parameter. Entity type of the
        issue. Supports single entity type and multiple
        entity types. Examples entityType=networkDevice
        (single entity type requested) entityType=network
        device&entityType=client (multiple entity types
        requested).
    type: str
  category:
    description:
      - >
        Category query parameter. Categories of the
        issue. Supports single category and multiple
        categories. Examples category=availability (single
        status requested) category=availability&category=onboarding
        (multiple categories requested).
    type: str
  deviceType:
    description:
      - >
        DeviceType query parameter. Device Type of the
        device to which this issue belongs to. Supports
        single device type and multiple device types.
        Examples deviceType=wireless controller (single
        device type requested) deviceType=wireless controller&deviceType=core
        (multiple device types requested).
    type: str
  name:
    description:
      - >
        Name query parameter. The name of the issue
        Examples name=ap_down (single issue name requested)
        name=ap_down&name=wlc_monitor (multiple issue
        names requested) Issue names can be retrieved
        using the API - /data/api/v1/assuranceIssueConfigurations.
    type: str
  issueId:
    description:
      - >
        IssueId query parameter. UUID of the issue Examples
        issueId=e52aecfe-b142-4287-a587-11a16ba6dd26
        (single issue id requested) issueId=e52aecfe-b142-4287-a587-11a16ba6dd26&issueId=864d0421-02c0-43a6-9c52-81cad45f66d8
        (multiple issue ids requested).
    type: str
  entityId:
    description:
      - >
        EntityId query parameter. Id of the entity for
        which this issue belongs to. For example, it
        could be mac address of AP or UUID of Sensor
        example 68 ca e4 79 3f 20 4de02167-901b-43cf-8822-cffd3caa286f
        Examples entityId=68 ca e4 79 3f 20 (single
        entity id requested) entityId=68 ca e4 79 3f
        20&entityId=864d0421-02c0-43a6-9c52-81cad45f66d8
        (multiple entity ids requested).
    type: str
  updatedBy:
    description:
      - >
        UpdatedBy query parameter. The user who last
        updated this issue. Examples updatedBy=admin
        (single updatedBy requested) updatedBy=admin&updatedBy=john
        (multiple updatedBy requested).
    type: str
  siteHierarchy:
    description:
      - >
        SiteHierarchy query parameter. The full hierarchical
        breakdown of the site tree starting from Global
        site name and ending with the specific site
        name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)
        This field supports wildcard asterisk (*) character
        search support. E.g. */San*, */San, /San* Examples
        `?siteHierarchy=Global/AreaName/BuildingName/FloorName`
        (single siteHierarchy requested) `?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Gl
        obal/AreaName2/BuildingName2/FloorName2` (multiple
        siteHierarchies requested).
    type: str
  siteHierarchyId:
    description:
      - >
        SiteHierarchyId query parameter. The full hierarchy
        breakdown of the site tree in id form starting
        from Global site UUID and ending with the specific
        site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)
        This field supports wildcard asterisk (*) character
        search support. E.g. `*uuid*, *uuid, uuid* Examples
        `?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid
        `(single siteHierarchyId requested) `?siteH
        ierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2
        /floorUuid2` (multiple siteHierarchyIds requested).
    type: str
  siteName:
    description:
      - >
        SiteName query parameter. The name of the site.
        (Ex. `FloorName`) This field supports wildcard
        asterisk (*) character search support. E.g.
        *San*, *San, San* Examples `?siteName=building1`
        (single siteName requested) `?siteName=building1&siteName=building2&siteName=building3`
        (multiple siteNames requested).
    type: str
  siteId:
    description:
      - >
        SiteId query parameter. The UUID of the site.
        (Ex. `flooruuid`) This field supports wildcard
        asterisk (*) character search support. E.g.*flooruuid*,
        *flooruuid, flooruuid* Examples `?siteId=id1`
        (single id requested) `?siteId=id1&siteId=id2&siteId=id3`
        (multiple ids requested).
    type: str
  fabricSiteId:
    description:
      - >
        FabricSiteId query parameter. The UUID of the
        fabric site. (Ex. "flooruuid") Examples fabricSiteId=e52aecfe-b142-4287-a587-11a16ba6dd26
        (single id requested) fabricSiteId=e52aecfe-b142-4287-a587-11a16ba6dd26,864d0421-02c0-43a6-9c52-81cad45f66d8
        (multiple ids requested).
    type: str
  fabricVnName:
    description:
      - >
        FabricVnName query parameter. The name of the
        fabric virtual network Examples fabricVnName=name1
        (single fabric virtual network name requested)
        fabricVnName=name1&fabricVnName=name2&fabricVnName=name3
        (multiple fabric virtual network names requested).
    type: str
  fabricTransitSiteId:
    description:
      - >
        FabricTransitSiteId query parameter. The UUID
        of the fabric transit site. (Ex. "flooruuid")
        Examples fabricTransitSiteId=e52aecfe-b142-4287-a587-11a16ba6dd26
        (single id requested) fabricTransitSiteId=e52ae
        cfe-b142-4287-a587-11a16ba6dd26&fabricTransitSiteId=864d0421-02c0-43a6-9c52-81cad45f66d8
        (multiple ids requested).
    type: str
  networkDeviceId:
    description:
      - >
        NetworkDeviceId query parameter. The list of
        Network Device Uuids. (Ex. `6bef213c-19ca-4170-8375-b694e251101c`)
        Examples `networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c`
        (single networkDeviceId requested) `networkDeviceId=6bef213c-19ca-4170-8375-
        b694e251101c&networkDeviceId=32219612-819e-4b5e-a96b-cf22aca13dd9&networkDeviceId=2541e9a7-b80d-4955-
        8aa2-79b233318ba0` (multiple networkDeviceIds
        with & separator).
    type: str
  networkDeviceIpAddress:
    description:
      - >
        NetworkDeviceIpAddress query parameter. The
        list of Network Device management IP Address.
        (Ex. `121.1.1.10`) This field supports wildcard
        (`*`) character-based search. Ex `*1.1*` or
        `1.1*` or `*1.1` Examples `networkDeviceIpAddress=121.1.1.10`
        `networkDeviceIpAddress=121.1.1.10&networkDeviceIpAddress=1
        72.20.1.10&networkDeviceIpAddress=10.10.20.10`
        (multiple networkDevice IP Address with & separator).
    type: str
  macAddress:
    description:
      - >
        MacAddress query parameter. The macAddress of
        the network device or client This field supports
        wildcard (`*`) character-based search. Ex `*AB
        AB AB*` or `AB AB AB*` or `*AB AB AB` Examples
        `macAddress=AB AB AB CD CD CD` (single macAddress
        requested) `macAddress=AB AB AB CD CD DC&macAddress=AB
        AB AB CD CD FE` (multiple macAddress requested).
    type: str
  view:
    description:
      - >
        View query parameter. The name of the View.
        Each view represents a specific data set. Please
        refer to the `IssuesView` Model for supported
        views. View is predefined set of attributes
        supported by the API. Only the attributes related
        to the given view will be part of the API response
        along with default attributes. If multiple views
        are provided, then response will contain attributes
        from all those views. If no views are specified,
        all attributes will be returned. | View Name
        | Included Attributes | | --- | --- | | `update`
        | updatedTime, updatedBy | | `site` | siteName,
        siteHierarchy, siteId, siteHierarchyId | Examples
        `view=update` (single view requested) `view=update&view=site`
        (multiple views requested).
    type: str
  attribute:
    description:
      - >
        Attribute query parameter. List of attributes
        related to the issue. If these are provided,
        then only those attributes will be part of response
        along with the default attributes. Please refer
        to the `IssuesResponseAttribute` Model for supported
        attributes. Examples `attribute=deviceType`
        (single attribute requested) `attribute=deviceType&attribute=updatedBy`
        (multiple attributes requested).
    type: str
  aiDriven:
    description:
      - AiDriven query parameter. Flag whether the issue
        is AI driven issue.
    type: bool
  fabricDriven:
    description:
      - FabricDriven query parameter. Flag whether the
        issue is related to a Fabric site, a virtual
        network or a transit.
    type: bool
  fabricSiteDriven:
    description:
      - FabricSiteDriven query parameter. Flag whether
        the issue is Fabric site driven issue.
    type: bool
  fabricVnDriven:
    description:
      - FabricVnDriven query parameter. Flag whether
        the issue is Fabric Virtual Network driven issue.
    type: bool
  fabricTransitDriven:
    description:
      - FabricTransitDriven query parameter. Flag whether
        the issue is Fabric Transit driven issue.
    type: bool
  id:
    description:
      - Id path parameter. The issue Uuid.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Issues
      GetAllTheDetailsAndSuggestedActionsOfAnIssueForTheGivenIssueId
    description: Complete reference of the GetAllTheDetailsAndSuggestedActionsOfAnIssueForTheGivenIssueId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-all-the-details-and-suggested-actions-of-an-issue-for-the-given-issue-id
  - name: Cisco DNA Center documentation for Issues
      GetTheDetailsOfIssuesForGivenSetOfFiltersKnowYourNetwork
    description: Complete reference of the GetTheDetailsOfIssuesForGivenSetOfFiltersKnowYourNetwork
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-the-details-of-issues-for-given-set-of-filters-know-your-network
notes:
  - SDK Method used are
    issues.Issues.get_all_the_details_and_suggested_actions_of_an_issue_for_the_given_issue_id,
    issues.Issues.get_the_details_of_issues_for_given_set_of_filters_know_your_network,
  - Paths used are
    get /dna/data/api/v1/assuranceIssues,
    get /dna/data/api/v1/assuranceIssues/{id},
"""

EXAMPLES = r"""
---
- name: Get all Assurance Issues
  cisco.dnac.assurance_issues_info:
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
    isGlobal: true
    priority: string
    severity: string
    status: string
    entityType: string
    category: string
    deviceType: string
    name: string
    issueId: string
    entityId: string
    updatedBy: string
    siteHierarchy: string
    siteHierarchyId: string
    siteName: string
    siteId: string
    fabricSiteId: string
    fabricVnName: string
    fabricTransitSiteId: string
    networkDeviceId: string
    networkDeviceIpAddress: string
    macAddress: string
    view: string
    attribute: string
    aiDriven: true
    fabricDriven: true
    fabricSiteDriven: true
    fabricVnDriven: true
    fabricTransitDriven: true
  register: result
- name: Get Assurance Issues by id
  cisco.dnac.assurance_issues_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    view: string
    attribute: string
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
        "issueId": "string",
        "name": "string",
        "description": "string",
        "summary": "string",
        "priority": "string",
        "severity": "string",
        "deviceType": "string",
        "category": "string",
        "entityType": "string",
        "entityId": "string",
        "firstOccurredTime": 0,
        "mostRecentOccurredTime": 0,
        "status": "string",
        "isGlobal": true,
        "updatedBy": "string",
        "updatedTime": 0,
        "notes": {},
        "siteId": {},
        "siteHierarchyId": {},
        "siteName": {},
        "siteHierarchy": {},
        "suggestedActions": [
          {
            "message": "string",
            "steps": [
              {}
            ]
          }
        ],
        "additionalAttributes": [
          {
            "key": "string",
            "value": "string"
          }
        ]
      },
      "version": "string"
    }
"""
