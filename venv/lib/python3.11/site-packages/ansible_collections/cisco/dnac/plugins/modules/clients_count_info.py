#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: clients_count_info
short_description: Information module for Clients Count
description:
  - Get all Clients Count. - > Retrieves the number
    of clients by applying basic filtering. For detailed
    information about the usage of the API, please refer
    to the Open API specification document - https //github.com/cisco-en-
    programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-clients1-1.0.0-resolved.yaml.
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
  type:
    description:
      - >
        Type query parameter. The client device type
        whether client is connected to network through
        Wired or Wireless medium.
    type: str
  osType:
    description:
      - >
        OsType query parameter. Client device operating
        system type. This field supports wildcard (`*`)
        character-based search. If the value contains
        the (`*`) character, please use the /query API
        for regex search. Ex `*iOS*` or `iOS*` or `*iOS`
        Examples `osType=iOS` (single osType requested)
        `osType=iOS&osType=Android` (multiple osType
        requested).
    type: str
  osVersion:
    description:
      - >
        OsVersion query parameter. Client device operating
        system version This field supports wildcard
        (`*`) character-based search. If the value contains
        the (`*`) character, please use the /query API
        for regex search. Ex `*14.3*` or `14.3*` or
        `*14.3` Examples `osVersion=14.3` (single osVersion
        requested) `osVersion=14.3&osVersion=10.1` (multiple
        osVersion requested).
    type: str
  siteHierarchy:
    description:
      - >
        SiteHierarchy query parameter. The full hierarchical
        breakdown of the site tree starting from Global
        site name and ending with the specific site
        name. The Root site is named "Global" (Ex. "Global/AreaName/BuildingName/FloorName")
        This field supports wildcard (`*`) character-based
        search. If the value contains the (`*`) character,
        please use the /query API for regex search.
        Ex `*BuildingName*` or `BuildingName*` or `*BuildingName`
        Examples `siteHierarchy=Global/AreaName/BuildingName/FloorName`
        (single siteHierarchy requested) `siteHierarchy=Global/AreaName/BuildingName1/FloorName1&siteHierarchy=G
        lobal/AreaName/BuildingName1/FloorName2` (multiple
        siteHierarchy requested).
    type: str
  siteHierarchyId:
    description:
      - >
        SiteHierarchyId query parameter. The full hierarchy
        breakdown of the site tree in id form starting
        from Global site UUID and ending with the specific
        site UUID. (Ex. "globalUuid/areaUuid/buildingUuid/floorUuid")
        This field supports wildcard (`*`) character-based
        search. Ex `*buildingUuid*` or `buildingUuid*`
        or `*buildingUuid` Examples `siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid`
        (single siteHierarchyId requested) `siteHie
        rarchyId=globalUuid/areaUuid/buildingUuid1/floorUuid1&siteHierarchyId=globalUuid/areaUuid/buildingUuid1/
        floorUuid2` (multiple siteHierarchyId requested).
    type: str
  siteId:
    description:
      - >
        SiteId query parameter. The site UUID without
        the top level hierarchy. (Ex."floorUuid") Examples
        `siteId=floorUuid` (single siteId requested)
        `siteId=floorUuid1&siteId=floorUuid2` (multiple
        siteId requested).
    type: str
  ipv4Address:
    description:
      - >
        Ipv4Address query parameter. IPv4 Address of
        the network entity either network device or
        client This field supports wildcard (`*`) character-based
        search. Ex `*1.1*` or `1.1*` or `*1.1` Examples
        `ipv4Address=1.1.1.1` (single ipv4Address requested)
        `ipv4Address=1.1.1.1&ipv4Address=2.2.2.2` (multiple
        ipv4Address requested).
    type: str
  ipv6Address:
    description:
      - >
        Ipv6Address query parameter. IPv6 Address of
        the network entity either network device or
        client This field supports wildcard (`*`) character-based
        search. Ex `*2001 db8*` or `2001 db8*` or `*2001
        db8` Examples `ipv6Address=2001 db8 0 0 0 0
        2 1` (single ipv6Address requested) `ipv6Address=2001
        db8 0 0 0 0 2 1&ipv6Address=2001 db8 85a3 8d3
        1319 8a2e 370 7348` (multiple ipv6Address requested).
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
  wlcName:
    description:
      - >
        WlcName query parameter. Wireless Controller
        name that reports the wireless client. This
        field supports wildcard (`*`) character-based
        search. If the value contains the (`*`) character,
        please use the /query API for regex search.
        Ex `*wlc-25*` or `wlc-25*` or `*wlc-25` Examples
        `wlcName=wlc-25` (single wlcName requested)
        `wlcName=wlc-25&wlc-34` (multiple wlcName requested).
    type: str
  connectedNetworkDeviceName:
    description:
      - >
        ConnectedNetworkDeviceName query parameter.
        Name of the neighbor network device that client
        is connected to. This field supports wildcard
        (`*`) character-based search. If the value contains
        the (`*`) character, please use the /query API
        for regex search. Ex `*ap-25*` or `ap-25*` or
        `*ap-25` Examples `connectedNetworkDeviceName=ap-25`
        (single connectedNetworkDeviceName requested)
        `connectedNetworkDeviceName=ap-25&ap-34` (multiple
        connectedNetworkDeviceName requested).
    type: str
  ssid:
    description:
      - >
        Ssid query parameter. SSID is the name of wireless
        network to which client connects to. It is also
        referred to as WLAN ID - Wireless Local Area
        Network Identifier. This field supports wildcard
        (`*`) character-based search. If the value contains
        the (`*`) character, please use the /query API
        for regex search. Ex `*Alpha*` or `Alpha*` or
        `*Alpha` Examples `ssid=Alpha` (single ssid
        requested) `ssid=Alpha&ssid=Guest` (multiple
        ssid requested).
    type: str
  band:
    description:
      - >
        Band query parameter. WiFi frequency band that
        client or Access Point operates. Band value
        is represented in Giga Hertz - GHz Examples
        `band=5GHZ` (single band requested) `band=2.4GHZ&band=6GHZ`
        (multiple band requested).
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Clients
      RetrievesTheTotalCountOfClientsByApplyingBasicFiltering
    description: Complete reference of the RetrievesTheTotalCountOfClientsByApplyingBasicFiltering
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-total-count-of-clients-by-applying-basic-filtering
notes:
  - SDK Method used are
    clients.Clients.retrieves_the_total_count_of_clients_by_applying_basic_filtering,
  - Paths used are
    get /dna/data/api/v1/clients/count,
"""

EXAMPLES = r"""
---
- name: Get all Clients Count
  cisco.dnac.clients_count_info:
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
    type: string
    osType: string
    osVersion: string
    siteHierarchy: string
    siteHierarchyId: string
    siteId: string
    ipv4Address: string
    ipv6Address: string
    macAddress: string
    wlcName: string
    connectedNetworkDeviceName: string
    ssid: string
    band: string
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
