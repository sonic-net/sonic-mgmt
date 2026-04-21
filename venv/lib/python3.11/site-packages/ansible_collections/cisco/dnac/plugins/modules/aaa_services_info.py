#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: aaa_services_info
short_description: Information module for Aaa Services
description:
  - Get all Aaa Services. - > Retrieves the list of
    AAA Services and offers basic filtering and sorting
    capabilities. For detailed information about the
    usage of the API, please refer to the Open API specification
    document - https //github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    AAAServices-1.0.0-resolved.yaml.
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
      - SortBy query parameter. Field name on which
        sorting needs to be done.
    type: str
  order:
    description:
      - Order query parameter. The sort order of the
        field ascending or descending.
    type: str
  serverIp:
    description:
      - >
        ServerIp query parameter. IP Address of the
        AAA Server. This parameter supports wildcard
        (`*`) character -based search. Example `10.76.81.*`
        or `*56.78*` or `*50.28` Examples serverIp=10.42.3.31
        (single IP Address is requested) serverIp=10.42.3.31&serverIp=name2&fabricVnName=name3
        (multiple IP Addresses are requested).
    type: str
  deviceId:
    description:
      - >
        DeviceId query parameter. The device UUID. Examples
        `deviceId=6bef213c-19ca-4170-8375-b694e251101c`
        (single deviceId is requested) `deviceId=6bef213c-19ca-4170-8375-b694e251101c&deviceId=32219612-819e-4b5e-a96b-cf22aca13dd9
        (multiple networkDeviceIds with & separator).
    type: str
  deviceName:
    description:
      - >
        DeviceName query parameter. Name of the device.
        This parameter supports wildcard (`*`) character
        -based search. Example `wnbu-sjc*` or `*wnbu-sjc*`
        or `*wnbu-sjc` Examples deviceName=wnbu-sjc24.cisco.com
        (single device name is requested) deviceName=wnbu-sjc24.cisco.com&deviceName=wnbu-sjc22.cisco.com
        (multiple device names are requested).
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
  deviceSiteHierarchyId:
    description:
      - >
        DeviceSiteHierarchyId query parameter. The full
        hierarchy breakdown of the site tree in id form
        starting from Global site UUID and ending with
        the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)
        This field supports wildcard asterisk (`*`)
        character search support. E.g. `*uuid*, *uuid,
        uuid*` Examples `?deviceSiteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid
        `(single siteHierarchyId requested) ` ?deviceSiteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&deviceSiteHierarchyId=globalUuid/areaU
        uid2/buildingUuid2/floorUuid2` (multiple siteHierarchyIds
        requested).
    type: str
  siteId:
    description:
      - >
        SiteId query parameter. The UUID of the site.
        (Ex. `flooruuid`) Examples `?siteId=id1` (single
        id requested) `?siteId=id1&siteId=id2&siteId=id3`
        (multiple ids requested).
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      RetrievesTheListOfAAAServicesForGivenParameters
    description: Complete reference of the RetrievesTheListOfAAAServicesForGivenParameters
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-list-of-aaa-services-for-given-parameters
notes:
  - SDK Method used are
    devices.Devices.retrieves_the_list_of_aaa_services_for_given_parameters,
  - Paths used are
    get /dna/data/api/v1/aaaServices,
"""

EXAMPLES = r"""
---
- name: Get all Aaa Services
  cisco.dnac.aaa_services_info:
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
    serverIp: string
    deviceId: string
    deviceName: string
    siteHierarchy: string
    deviceSiteHierarchyId: string
    siteId: string
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
          "serverIp": "string",
          "deviceId": "string",
          "deviceName": "string",
          "deviceFamily": "string",
          "deviceSiteHierarchy": "string",
          "deviceSiteId": "string",
          "deviceSiteHierarchyId": "string",
          "transactions": 0,
          "failedTransactions": 0,
          "successfulTransactions": 0,
          "eapTransactions": 0,
          "eapFailedTransactions": 0,
          "eapSuccessfulTransactions": 0,
          "mabTransactions": 0,
          "mabFailedTransactions": 0,
          "mabSuccessfulTransactions": 0,
          "latency": 0,
          "eapLatency": 0,
          "mabLatency": 0
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
