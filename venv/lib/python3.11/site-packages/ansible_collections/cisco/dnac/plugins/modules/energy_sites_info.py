#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: energy_sites_info
short_description: Information module for Energy Sites
description:
  - Get all Energy Sites. - > Retrieves a list of sites
    with energy data based on the specified query parameters.
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
  startTime:
    description:
      - >
        StartTime query parameter. Start time from which
        API queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive. If `startTime` is not provided,
        API will default to one day before `endTime`.
    type: float
  endTime:
    description:
      - >
        EndTime query parameter. End time to which API
        queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive. If `endTime` is not provided,
        API will default to one day after `startTime`.
        If `startTime` is not provided either, API will
        default to current time.
    type: float
  limit:
    description:
      - Limit query parameter. Maximum number of records
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
      - SortBy query parameter. A field within the response
        to sort by.
    type: str
  order:
    description:
      - Order query parameter. The sort order of the
        field ascending or descending.
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
  siteHierarchyId:
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
  siteName:
    description:
      - >
        SiteName query parameter. The name of the site.
        (Ex. `FloorName`) This field supports wildcard
        asterisk (`*`) character search support. E.g.
        `*San*, *San, San*` Examples `?siteName=building1`
        (single siteName requested) `?siteName=building1&siteName=building2&siteName=building3`
        (multiple siteNames requested).
    type: str
  siteType:
    description:
      - >
        SiteType query parameter. The type of the site.
        A site can be an area, building, or floor. Default
        when not provided will be `floor,building,area`
        Examples `?siteType=area` (single siteType requested)
        `?siteType=area&siteType=building&siteType=floor`
        (multiple siteTypes requested).
    type: str
  deviceCategory:
    description:
      - >
        DeviceCategory query parameter. The list of
        device categories. Note that this filter specifies
        which devices will be included when calculating
        energy consumption values, rather than specifying
        the list of returned sites. Examples `deviceCategory=Switch`
        (single device category requested) `deviceCategory=Switch&deviceCategory=Router`
        (multiple device categories with comma separator).
    type: str
  siteId:
    description:
      - >
        SiteId query parameter. The UUID of the site.
        (Ex. `flooruuid`) Examples `?siteId=id1` (single
        id requested) `?siteId=id1&siteId=id2&siteId=id3`
        (multiple ids requested).
    type: str
  views:
    description:
      - >
        Views query parameter. The specific summary
        view being requested. This is an optional parameter
        which can be passed to get one or more of the
        specific health data summaries associated with
        sites. ### Response data proviced by each view
        1. **Site** id, siteHierarchy, siteHierarchyId,
        siteType, latitude, longitude 2. **Energy**
        energyConsumed, estimatedCost, estimatedEmission,
        carbonIntensity, numberOfDevices When this query
        parameter is not added the default summaries
        are **site,energy** Examples views=site (single
        view requested) views=site,energy (multiple
        views requested).
    type: str
  attribute:
    description:
      - >
        Attribute query parameter. Supported Attributes
        id, siteHierarchy, siteHierarchyId, siteType,
        latitude, longitude, energyConsumed, estimatedCost,
        estimatedEmission, carbonIntensity, numberOfDevices
        If length of attribute list is too long, please
        use 'view' param instead. Examples attribute=siteHierarchy
        (single attribute requested) attribute=siteHierarchy&attribute=energyConsumed
        (multiple attributes requested).
    type: str
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
  - name: Cisco DNA Center documentation for Sites GetSitesEnergy
    description: Complete reference of the GetSitesEnergy
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-sites-energy
notes:
  - SDK Method used are
    sites.Sites.get_sites_energy,
  - Paths used are
    get /dna/data/api/v1/energy/sites,
"""

EXAMPLES = r"""
---
- name: Get all Energy Sites
  cisco.dnac.energy_sites_info:
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
    siteHierarchy: string
    siteHierarchyId: string
    siteName: string
    siteType: string
    deviceCategory: string
    siteId: string
    views: string
    attribute: string
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
      "response": [
        {
          "id": "string",
          "siteName": "string",
          "siteHierarchy": "string",
          "siteHierarchyId": "string",
          "siteType": "string",
          "latitude": 0,
          "longitude": 0,
          "deviceCategories": [
            "string"
          ],
          "energyConsumed": 0,
          "estimatedCost": 0,
          "estimatedEmission": 0,
          "carbonIntensity": 0,
          "numberOfDevices": 0
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
