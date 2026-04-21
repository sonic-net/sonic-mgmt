#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: interfaces_count_info
short_description: Information module for Interfaces
  Count
description:
  - Get all Interfaces Count. - > Gets the total Network
    device interface counts. For detailed information
    about the usage of the API, please refer to the
    Open API specification document - https //github.com/cisco-en-programmability/catalyst-center-
    api-specs/blob/main/Assurance/CE_Cat_Center_Org-interfaces-2.0.0-resolved.yaml.
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
  siteId:
    description:
      - >
        SiteId query parameter. The UUID of the site.
        (Ex. `flooruuid`) Examples `?siteId=id1` (single
        id requested) `?siteId=id1&siteId=id2&siteId=id3`
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
  networkDeviceMacAddress:
    description:
      - >
        NetworkDeviceMacAddress query parameter. The
        list of Network Device MAC Address. (Ex. `64
        f6 9d 07 9a 00`) This field supports wildcard
        (`*`) character-based search. Ex `*AB AB AB*`
        or `AB AB AB*` or `*AB AB AB` Examples `networkDeviceMacAddress=64
        f6 9d 07 9a 00` `networkDeviceMacAddress=64
        f6 9d 07 9a 00&networkDeviceMacAddress=70 56
        9d 07 ac 77` (multiple networkDevice MAC addresses
        with & separator).
    type: str
  interfaceId:
    description:
      - >
        InterfaceId query parameter. The list of Interface
        Uuids. (Ex. `6bef213c-19ca-4170-8375-b694e251101c`)
        Examples `interfaceId=6bef213c-19ca-4170-8375-b694e251101c`
        (single interface uuid ) `interfaceId=6bef21
        3c-19ca-4170-8375-b694e251101c&32219612-819e-4b5e-a96b-cf22aca13dd9&2541e9a7-b80d-4955-8aa2-
        79b233318ba0` (multiple Interface uuid with
        & separator).
    type: str
  interfaceName:
    description:
      - >
        InterfaceName query parameter. The list of Interface
        name (Ex. `GigabitEthernet1/0/1`) This field
        supports wildcard (`*`) character-based search.
        Ex `*1/0/1*` or `1/0/1*` or `*1/0/1` Examples
        `interfaceNames=GigabitEthernet1/0/1` (single
        interface name) `interfaceNames=GigabitEthernet1/0/1&GigabitEthernet2/0/1&GigabitEthernet3/0/1`
        (multiple interface names with & separator).
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetsTheTotalNetworkDeviceInterfaceCountsInTheSpecified
      TimeRangeWhenThereIsNoStartAndEndTimeSpecifiedReturnsTheLatestInterfacesTotalCount
    description:
      >
      Complete reference of the
      GetsTheTotalNetworkDeviceInterfaceCountsInTheSpecified
      TimeRangeWhenThereIsNoStartAndEndTimeSpecifiedReturnsTheLatestInterfacesTotalCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!gets-the-total-network-device-interface-counts-in-the-specified-time-range-
          when-there-is-no-start-and-end-time-specified-returns-the-latest-interfaces-total-count
notes:
  - SDK Method used are
    devices.Devices.gets_the_total_network_device_interface_counts,
  - Paths used are
    get /dna/data/api/v1/interfaces/count,
"""

EXAMPLES = r"""
---
- name: Get all Interfaces Count
  cisco.dnac.interfaces_count_info:
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
    siteHierarchy: string
    siteHierarchyId: string
    siteId: string
    networkDeviceId: string
    networkDeviceIpAddress: string
    networkDeviceMacAddress: string
    interfaceId: string
    interfaceName: string
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
