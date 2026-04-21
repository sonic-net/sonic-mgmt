#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: clients_info
short_description: Information module for Clients
description:
  - Get all Clients.
  - Get Clients by id. - > Retrieves specific client
    information matching the MAC address. For detailed
    information about the usage of the API, please refer
    to the Open API specification document - https //github.com/cisco-en-
    programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-clients1-1.0.0-resolved.yaml.
    - > Retrieves the list of clients, while also offering
    basic filtering and sorting capabilities. For detailed
    information about the usage of the API, please refer
    to the Open API specification document - https //github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    clients1-1.0.0-resolved.yaml.
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
  view:
    description:
      - >
        View query parameter. Client related Views Refer
        to ClientView schema for list of views supported
        Examples `view=Wireless` (single view requested)
        `view=WirelessHealth&view=WirelessTraffic` (multiple
        view requested).
    type: str
  attribute:
    description:
      - >
        Attribute query parameter. List of attributes
        related to resource that can be requested to
        only be part of the response along with the
        required attributes. Refer to ClientAttribute
        schema for list of attributes supported Examples
        `attribute=band` (single attribute requested)
        `attribute=band&attribute=ssid&attribute=overallScore`
        (multiple attribute requested).
    type: str
  id:
    description:
      - >
        Id path parameter. Id is the client mac address.
        It can be specified is any notational conventions
        01 23 45 67 89 AB or 01-23-45-67-89-AB or 0123.4567.89AB
        and is case insensitive.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Clients
      RetrievesSpecificClientInformationMatchingTheMACAddress
    description: Complete reference of the RetrievesSpecificClientInformationMatchingTheMACAddress
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-specific-client-information-matching-the-mac-address
  - name: Cisco DNA Center documentation for Clients
      RetrievesTheListOfClientsWhileAlsoOfferingBasicFilteringAndSortingCapabilities
    description: Complete reference of the RetrievesTheListOfClientsWhileAlsoOfferingBasicFilteringAndSortingCapabilities
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-list-of-clients-while-also-offering-basic-filtering-and-sorting-capabilities
notes:
  - SDK Method used are
    clients.Clients.retrieves_specific_client_information_matching_the_macaddress,
    clients.Clients.retrieves_the_list_of_clients_while_also_offering_basic_filtering_and_sorting_capabilities,
  - Paths used are
    get /dna/data/api/v1/clients,
    get
    /dna/data/api/v1/clients/{id},
"""

EXAMPLES = r"""
---
- name: Get all Clients
  cisco.dnac.clients_info:
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
    view: string
    attribute: string
  register: result
- name: Get Clients by id
  cisco.dnac.clients_info:
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
        "id": "string",
        "macAddress": "string",
        "type": "string",
        "name": "string",
        "userId": "string",
        "username": "string",
        "ipv4Address": "string",
        "ipv6Addresses": [
          "string"
        ],
        "vendor": "string",
        "osType": "string",
        "osVersion": "string",
        "formFactor": "string",
        "siteHierarchy": "string",
        "siteHierarchyId": "string",
        "siteId": "string",
        "lastUpdatedTime": 0,
        "connectionStatus": "string",
        "tracked": "string",
        "isPrivateMacAddress": true,
        "health": {
          "overallScore": 0,
          "onboardingScore": 0,
          "connectedScore": 0,
          "linkErrorPercentageThreshold": 0,
          "isLinkErrorIncluded": true,
          "rssiThreshold": 0,
          "snrThreshold": 0,
          "isRssiIncluded": true,
          "isSnrIncluded": true
        },
        "traffic": {
          "txBytes": 0,
          "rxBytes": 0,
          "usage": 0,
          "rxPackets": 0,
          "txPackets": 0,
          "rxRate": 0,
          "txRate": 0,
          "rxLinkErrorPercentage": 0,
          "txLinkErrorPercentage": 0,
          "rxRetries": 0,
          "rxRetryPercentage": 0,
          "txDrops": 0,
          "txDropPercentage": 0,
          "dnsRequestCount": 0,
          "dnsResponseCount": 0
        },
        "connectedNetworkDevice": {
          "connectedNetworkDeviceId": "string",
          "connectedNetworkDeviceName": "string",
          "connectedNetworkDeviceManagementIp": "string",
          "connectedNetworkDeviceMac": "string",
          "connectedNetworkDeviceType": "string",
          "interfaceName": "string",
          "interfaceSpeed": 0,
          "duplexMode": "string"
        },
        "connection": {
          "vlanId": "string",
          "sessionDuration": 0,
          "vnId": "string",
          "l2Vn": "string",
          "l3Vn": "string",
          "securityGroupTag": "string",
          "linkSpeed": 0,
          "bridgeVMMode": "string",
          "band": "string",
          "ssid": "string",
          "authType": "string",
          "wlcName": "string",
          "wlcId": "string",
          "apMac": "string",
          "apEthernetMac": "string",
          "apMode": "string",
          "radioId": 0,
          "channel": "string",
          "channelWidth": "string",
          "protocol": "string",
          "protocolCapability": "string",
          "upnId": "string",
          "upnName": "string",
          "upnOwner": "string",
          "upnDuid": "string",
          "rssi": 0,
          "snr": 0,
          "dataRate": 0,
          "isIosAnalyticsCapable": true
        },
        "onboarding": {
          "avgRunDuration": 0,
          "maxRunDuration": 0,
          "avgAssocDuration": 0,
          "maxAssocDuration": 0,
          "avgAuthDuration": 0,
          "maxAuthDuration": 0,
          "avgDhcpDuration": 0,
          "maxDhcpDuration": 0,
          "maxRoamingDuration": 0,
          "aaaServerIp": "string",
          "dhcpServerIp": "string",
          "onboardingTime": 0,
          "authDoneTime": 0,
          "assocDoneTime": 0,
          "dhcpDoneTime": 0,
          "roamingTime": 0,
          "failedRoamingCount": 0,
          "successfulRoamingCount": 0,
          "totalRoamingAttempts": 0,
          "assocFailureReason": "string",
          "aaaFailureReason": "string",
          "dhcpFailureReason": "string",
          "otherFailureReason": "string",
          "latestFailureReason": "string"
        },
        "latency": {
          "video": 0,
          "voice": 0,
          "bestEffort": 0,
          "background": 0
        }
      },
      "version": "string"
    }
"""
