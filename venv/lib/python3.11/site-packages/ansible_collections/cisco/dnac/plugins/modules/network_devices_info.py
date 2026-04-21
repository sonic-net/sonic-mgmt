#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_info
short_description: Information module for Network Devices
description:
  - Get all Network Devices.
  - Get Network Devices by id. - > Gets the Network
    Device details based on the provided query parameters.
    When there is no start and end time specified returns
    the latest device details. For detailed information
    about the usage of the API, please refer to the
    Open API specification document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceNetworkDevices-2.0.1-resolved.yaml.
    - > Returns the device data for the given device
    Uuid in the specified start and end time range.
    When there is no start and end time specified returns
    the latest available data for the given Id. For
    detailed information about the usage of the API,
    please refer to the Open API specification document
    - https //github.com/cisco-en- programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    AssuranceNetworkDevices-2.0.1-resolved.yaml.
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
  managementIpAddress:
    description:
      - >
        ManagementIpAddress query parameter. The list
        of entity management IP Address. It can be either
        Ipv4 or Ipv6 address or combination of both(Ex.
        "121.1.1.10") This field supports wildcard (`*`)
        character-based search. Ex `*1.1*` or `1.1*`
        or `*1.1` Examples managementIpAddresses=121.1.1.10
        managementIpAddresses=121.1.1.10&managementIpAddresses=172.20.1.10&managementIpAddresses=200
        10&=managementIpAddresses172.20.3.4 (multiple
        entity IP Address with & separator).
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
  family:
    description:
      - >
        Family query parameter. The list of network
        device family names Examples family=Switches
        and Hubs (single network device family name
        )family=Switches and Hubs&family=Router&family=Wireless
        Controller (multiple Network device family names
        with & separator). This field is not case sensitive.
    type: str
  type:
    description:
      - >
        Type query parameter. The list of network device
        type This field supports wildcard (`*`) character-based
        search. Ex `*9407R*` or `*9407R` or `9407R*`
        Examples type=SwitchesCisco Catalyst 9407R Switch
        (single network device types ) type=Cisco Catalyst
        38xx stack-able ethernet switch&type=Cisco 3945
        Integrated Services Router G2 (multiple Network
        device types with & separator).
    type: str
  role:
    description:
      - >
        Role query parameter. The list of network device
        role. Examples role=CORE, role=CORE&role=ACCESS&role=ROUTER
        (multiple Network device roles with & separator).
        This field is not case sensitive.
    type: str
  serialNumber:
    description:
      - >
        SerialNumber query parameter. The list of network
        device serial numbers. This field supports wildcard
        (`*`) character-based search. Ex `*MS1SV*` or
        `MS1SV*` or `*MS1SV` Examples serialNumber=9FUFMS1SVAX
        serialNumber=9FUFMS1SVAX&FCW2333Q0BY&FJC240617JX(multiple
        Network device serial number with & separator).
    type: str
  maintenanceMode:
    description:
      - MaintenanceMode query parameter. The device
        maintenanceMode status true or false.
    type: bool
  softwareVersion:
    description:
      - >
        SoftwareVersion query parameter. The list of
        network device software version This field supports
        wildcard (`*`) character-based search. Ex `*17.8*`
        or `*17.8` or `17.8*` Examples softwareVersion=2.3.4.0
        (single network device software version ) softwareVersion=17.9.3.23&softwareVersion=17.7.1.2&softwareVersion=*.17.7
        (multiple Network device software versions with
        & separator).
    type: str
  healthScore:
    description:
      - >
        HealthScore query parameter. The list of entity
        health score categories Examples healthScore=good,
        healthScore=good&healthScore=fair (multiple
        entity healthscore values with & separator).
        This field is not case sensitive.
    type: str
  view:
    description:
      - >
        View query parameter. The List of Network Device
        model views. Please refer to ```NetworkDeviceView```
        section in the Open API specification document
        mentioned in the description.
    type: str
  attribute:
    description:
      - >
        Attribute query parameter. The List of Network
        Device model attributes. Please refer to ```NetworkDeviceAttribute```
        section in the Open API specification document
        mentioned in the description.
    type: str
  fabricSiteId:
    description:
      - >
        FabricSiteId query parameter. The fabric site
        Id or list to fabric site Ids to filter the
        data This field supports wildcard asterisk (*)
        character search support. E.g. *uuid*, *uuid,
        uuid* Examples `?fabricSiteId=fabricSiteUuid)
        ?fabricSiteId=fabricSiteUuid1&fabricSiteId=fabricSiteUuid2
        (multiple fabricSiteIds requested).
    type: str
  l2Vn:
    description:
      - >
        L2Vn query parameter. The L2 Virtual Network
        Id or list to Virtual Network Ids to filter
        the data This field supports wildcard asterisk
        (*) character search support. E.g. *uuid*, *uuid,
        uuid* Examples `?l2Vn=virtualNetworkId ?l2Vn=virtualNetworkId1&l2Vn=virtualNetworkId2
        (multiple virtualNetworkId's requested).
    type: str
  l3Vn:
    description:
      - >
        L3Vn query parameter. The L3 Virtual Network
        Id or list to Virtual Network Ids to filter
        the data This field supports wildcard asterisk
        (*) character search support. E.g. *uuid*, *uuid,
        uuid* Examples `?l3Vn=virtualNetworkId ?l3Vn=virtualNetworkId1&l3Vn=virtualNetworkId2
        (multiple virtualNetworkId's requested).
    type: str
  transitNetworkId:
    description:
      - >
        TransitNetworkId query parameter. The Transit
        Network Id or list to Transit Network Ids to
        filter the data This field supports wildcard
        asterisk (*) character search support. E.g.
        *uuid*, *uuid, uuid* Examples `?transitNetworkId=transitNetworkId
        ?transitNetworkId=transitNetworkuuid1&transitNetworkId=transitNetworkuuid1
        (multiple transitNetworkIds requested.
    type: str
  fabricRole:
    description:
      - >
        FabricRole query parameter. The list of fabric
        device role. Examples fabricRole=BORDER, fabricRole=BORDER&fabricRole=EDGE
        (multiple fabric device roles with & separator)
        Available values BORDER, EDGE, MAP-SERVER, LEAF,
        SPINE, TRANSIT-CP, EXTENDED-NODE, WLC, UNIFIED-AP.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetTheDeviceDataForTheGivenDeviceIdUuid
    description: Complete reference of the GetTheDeviceDataForTheGivenDeviceIdUuid
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-the-device-data-for-the-given-device-id-uuid
  - name: Cisco DNA Center documentation for Devices
      GetsTheNetworkDeviceDetailsBasedOnTheProvidedQueryParameters
    description: Complete reference of the GetsTheNetworkDeviceDetailsBasedOnTheProvidedQueryParameters
      API.
    link: https://developer.cisco.com/docs/dna-center/#!gets-the-network-device-details-based-on-the-provided-query-parameters
notes:
  - SDK Method used are
    devices.Devices.get_the_device_data_for_the_given_device_id_uuid,
    devices.Devices.gets_the_network_device_details_based_on_the_provided_query_parameters,
  - Paths used are
    get /dna/data/api/v1/networkDevices,
    get /dna/data/api/v1/networkDevices/{id},
"""

EXAMPLES = r"""
---
- name: Get all Network Devices
  cisco.dnac.network_devices_info:
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
    siteId: string
    id: string
    managementIpAddress: string
    macAddress: string
    family: string
    type: string
    role: string
    serialNumber: string
    maintenanceMode: true
    softwareVersion: string
    healthScore: string
    view: string
    attribute: string
    fabricSiteId: string
    l2Vn: string
    l3Vn: string
    transitNetworkId: string
    fabricRole: string
  register: result
- name: Get Network Devices by id
  cisco.dnac.network_devices_info:
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
        "name": "string",
        "managementIpAddress": "string",
        "platformId": "string",
        "deviceFamily": "string",
        "serialNumber": "string",
        "macAddress": "string",
        "deviceSeries": "string",
        "softwareVersion": "string",
        "productVendor": "string",
        "deviceRole": "string",
        "deviceType": "string",
        "communicationState": "string",
        "collectionStatus": "string",
        "haStatus": "string",
        "lastBootTime": 0,
        "siteHierarchyId": "string",
        "siteHierarchy": "string",
        "siteId": "string",
        "deviceGroupHierarchyId": "string",
        "tagNames": [
          "string"
        ],
        "stackType": "string",
        "osType": "string",
        "ringStatus": true,
        "maintenanceModeEnabled": true,
        "upTime": 0,
        "ipv4Address": "string",
        "ipv6Address": "string",
        "redundancyMode": "string",
        "featureFlagList": [
          "string"
        ],
        "haLastResetReason": "string",
        "redundancyPeerStateDerived": "string",
        "redundancyPeerState": "string",
        "redundancyStateDerived": "string",
        "redundancyState": "string",
        "wiredClientCount": 0,
        "wirelessClientCount": 0,
        "portCount": 0,
        "physicalPortCount": 0,
        "virtualPortCount": 0,
        "clientCount": 0,
        "apDetails": {
          "connectedWlcName": "string",
          "policyTagName": "string",
          "apOperationalState": "string",
          "powerSaveMode": "string",
          "operationalMode": "string",
          "resetReason": "string",
          "protocol": "string",
          "powerMode": "string",
          "connectedTime": 0,
          "ledFlashEnabled": true,
          "ledFlashSeconds": 0,
          "subMode": "string",
          "homeApEnabled": true,
          "powerType": "string",
          "apType": "string",
          "adminState": "string",
          "icapCapability": "string",
          "regulatoryDomain": "string",
          "ethernetMac": "string",
          "rfTagName": "string",
          "siteTagName": "string",
          "powerSaveModeCapable": "string",
          "powerProfile": "string",
          "flexGroup": "string",
          "powerCalendarProfile": "string",
          "apGroup": "string",
          "radios": [
            {
              "id": "string",
              "band": "string",
              "noise": 0,
              "airQuality": 0,
              "interference": 0,
              "trafficUtil": 0,
              "utilization": 0,
              "clientCount": 0
            }
          ]
        },
        "metricsDetails": {
          "overallHealthScore": 0,
          "cpuUtilization": 0,
          "cpuScore": 0,
          "memoryUtilization": 0,
          "memoryScore": 0,
          "avgTemperature": 0,
          "maxTemperature": 0,
          "discardScore": 0,
          "discardInterfaces": [
            "string"
          ],
          "errorScore": 0,
          "errorInterfaces": [
            "string"
          ],
          "interDeviceLinkScore": 0,
          "interDeviceConnectedDownInterfaces": [
            "string"
          ],
          "linkUtilizationScore": 0,
          "highLinkUtilizationInterfaces": [
            "string"
          ],
          "freeTimerScore": 0,
          "freeTimer": 0,
          "packetPoolScore": 0,
          "packetPool": 0,
          "freeMemoryBufferScore": 0,
          "freeMemoryBuffer": 0,
          "wqePoolScore": 0,
          "wqePool": 0,
          "apCount": 0,
          "noiseScore": 0,
          "utilizationScore": 0,
          "interferenceScore": 0,
          "airQualityScore": 0
        },
        "fabricDetails": {
          "fabricRole": [
            "string"
          ],
          "fabricSiteName": "string",
          "transitFabrics": [
            "string"
          ],
          "l2Vns": [
            "string"
          ],
          "l3Vns": [
            "string"
          ],
          "fabricSiteId": "string",
          "networkProtocol": "string"
        },
        "switchPoeDetails": {
          "portCount": 0,
          "usedPortCount": 0,
          "freePortCount": 0,
          "powerConsumed": 0,
          "poePowerConsumed": 0,
          "systemPowerConsumed": 0,
          "powerBudget": 0,
          "poePowerAllocated": 0,
          "systemPowerAllocated": 0,
          "powerRemaining": 0,
          "poeVersion": "string",
          "chassisCount": 0,
          "moduleCount": 0,
          "moduleDetails": [
            {
              "moduleId": "string",
              "chassisId": "string",
              "modulePortCount": 0,
              "moduleUsedPortCount": 0,
              "moduleFreePortCount": 0,
              "modulePowerConsumed": 0,
              "modulePoePowerConsumed": 0,
              "moduleSystemPowerConsumed": 0,
              "modulePowerBudget": 0,
              "modulePoePowerAllocated": 0,
              "moduleSystemPowerAllocated": 0,
              "modulePowerRemaining": 0,
              "interfacePowerMax": 0
            }
          ]
        },
        "fabricMetricsDetails": {
          "overallFabricScore": 0,
          "fabricTransitScore": 0,
          "fabricSiteScore": 0,
          "fabricVnScore": 0,
          "fabsiteFcpScore": 0,
          "fabsiteInfraScore": 0,
          "fabsiteFsconnScore": 0,
          "vnExitScore": 0,
          "vnFcpScore": 0,
          "vnStatusScore": 0,
          "vnServiceScore": 0,
          "transitControlPlaneScore": 0,
          "transitServicesScore": 0,
          "tcpConnScore": 0,
          "bgpBgpSiteScore": 0,
          "vniStatusScore": 0,
          "pubsubTransitConnScore": 0,
          "bgpPeerInfraVnScore": 0,
          "internetAvailScore": 0,
          "bgpEvpnScore": 0,
          "lispTransitConnScore": 0,
          "ctsEnvDataDownloadScore": 0,
          "pubsubInfraVnScore": 0,
          "peerScore": 0,
          "bgpPeerScore": 0,
          "remoteInternetAvailScore": 0,
          "bgpTcpScore": 0,
          "pubsubSessionScore": 0,
          "aaaStatusScore": 0,
          "lispCpConnScore": 0,
          "bgpPubsubSiteScore": 0,
          "mcastScore": 0,
          "portChannelScore": 0
        },
        "aggregateAttributes": [
          {
            "name": "string",
            "function": "string",
            "value": 0
          }
        ]
      },
      "version": "string"
    }
"""
