#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: assurance_events_info
short_description: Information module for Assurance
  Events
description:
  - Get all Assurance Events.
  - Get Assurance Events by id. - > API to fetch the
    details of an assurance event using event `id`.
    For detailed information about the usage of the
    API, please refer to the Open API specification
    document - https //github.com/cisco-en- programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    AssuranceEvents-1.0.0-resolved.yaml. - > Returns
    the list of events discovered by Catalyst Center,
    determined by the complex filters. Please refer
    to the 'API Support Documentation' section to understand
    which fields are supported. For detailed information
    about the usage of the API, please refer to the
    Open API specification document - https //github.com/cisco-en-
    programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    AssuranceEvents-1.0.0-resolved.yaml.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceFamily:
    description:
      - >
        DeviceFamily query parameter. Device family.
        Please note that multiple families across network
        device type and client type is not allowed.
        For example, choosing `Routers` along with `Wireless
        Client` or `Unified AP` is not supported. Examples
        `deviceFamily=Switches and Hubs` (single deviceFamily
        requested) `deviceFamily=Switches and Hubs&deviceFamily=Routers`
        (multiple deviceFamily requested).
    type: str
  startTime:
    description:
      - >
        StartTime query parameter. Start time from which
        API queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive. If `startTime` is not provided,
        API will default to current time minus 24 hours.
    type: float
  endTime:
    description:
      - >
        EndTime query parameter. End time to which API
        queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive. If `endTime` is not provided,
        API will default to current time.
    type: float
  messageType:
    description:
      - >
        MessageType query parameter. Message type for
        the event. Examples `messageType=Syslog` (single
        messageType requested) `messageType=Trap&messageType=Syslog`
        (multiple messageType requested).
    type: str
  severity:
    description:
      - >
        Severity query parameter. Severity of the event
        between 0 and 6. This is applicable only for
        events related to network devices (other than
        AP) and `Wired Client` events. | Value | Severity
        | | ----- | ----------- | | 0 | Emergency |
        | 1 | Alert | | 2 | Critical | | 3 | Error |
        | 4 | Warning | | 5 | Notice | | 6 | Info |
        Examples `severity=0` (single severity requested)
        `severity=0&severity=1` (multiple severity requested).
    type: float
  siteId:
    description:
      - >
        SiteId query parameter. The UUID of the site.
        (Ex. `flooruuid`) Examples `?siteId=id1` (single
        siteId requested) `?siteId=id1&siteId=id2&siteId=id3`
        (multiple siteId requested).
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
        /floorUuid2` (multiple siteHierarchyId requested).
    type: str
  networkDeviceName:
    description:
      - >
        NetworkDeviceName query parameter. Network device
        name. This parameter is applicable for network
        device related families. This field supports
        wildcard (`*`) character-based search. Ex `*Branch*`
        or `Branch*` or `*Branch` Examples `networkDeviceName=Branch-3-Gateway`
        (single networkDeviceName requested) `networkDeviceName=Branch-3-Gateway&networkDeviceName=Branch-3-Switch`
        (multiple networkDeviceName requested).
    type: str
  networkDeviceId:
    description:
      - >
        NetworkDeviceId query parameter. The list of
        Network Device Uuids. (Ex. `6bef213c-19ca-4170-8375-b694e251101c`)
        Examples `networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c`
        (single networkDeviceId requested) `networkDeviceId=6bef213c-19ca-4170-8375-
        b694e251101c&networkDeviceId=32219612-819e-4b5e-a96b-cf22aca13dd9&networkDeviceId=2541e9a7-b80d-4955-
        8aa2-79b233318ba0` (multiple networkDeviceId
        with & separator).
    type: str
  apMac:
    description:
      - >
        ApMac query parameter. MAC address of the access
        point. This parameter is applicable for `Unified
        AP` and `Wireless Client` events. This field
        supports wildcard (`*`) character-based search.
        Ex `*50 0F*` or `50 0F*` or `*50 0F` Examples
        `apMac=50 0F 80 0F F7 E0` (single apMac requested)
        `apMac=50 0F 80 0F F7 E0&apMac=18 80 90 AB 7E
        A0` (multiple apMac requested).
    type: str
  clientMac:
    description:
      - >
        ClientMac query parameter. MAC address of the
        client. This parameter is applicable for `Wired
        Client` and `Wireless Client` events. This field
        supports wildcard (`*`) character-based search.
        Ex `*66 2B*` or `66 2B*` or `*66 2B` Examples
        `clientMac=66 2B B8 D2 01 56` (single clientMac
        requested) `clientMac=66 2B B8 D2 01 56&clientMac=DC
        A6 32 F5 5A 89` (multiple clientMac requested).
    type: str
  attribute:
    description:
      - >
        Attribute query parameter. The list of attributes
        that needs to be included in the response. If
        this parameter is not provided, then basic attributes
        (`id`, `name`, `timestamp`, `details`, `messageType`,
        `siteHierarchyId`, `siteHierarchy`, `deviceFamily`,
        `networkDeviceId`, `networkDeviceName`, `managementIpAddress`)
        would be part of the response. Examples `attribute=name`
        (single attribute requested) `attribute=name&attribute=networkDeviceName`
        (multiple attribute requested).
    type: str
  view:
    description:
      - >
        View query parameter. The list of events views.
        Please refer to `EventViews` for the supported
        list Examples `view=network` (single view requested)
        `view=network&view=ap` (multiple view requested).
    type: str
  offset:
    description:
      - >
        Offset query parameter. Specifies the starting
        point within all records returned by the API.
        It's one based offset. The starting value is
        1.
    type: int
  limit:
    description:
      - Limit query parameter. Maximum number of records
        to return.
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
  id:
    description:
      - Id path parameter. Unique identifier for the
        event.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetDetailsOfASingleAssuranceEvent
    description: Complete reference of the GetDetailsOfASingleAssuranceEvent
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-details-of-a-single-assurance-event
  - name: Cisco DNA Center documentation for Devices
      QueryAssuranceEvents
    description: Complete reference of the QueryAssuranceEvents
      API.
    link: https://developer.cisco.com/docs/dna-center/#!query-assurance-events
notes:
  - SDK Method used are
    devices.Devices.get_details_of_a_single_assurance_event,
    devices.Devices.query_assurance_events,
  - Paths used are
    get /dna/data/api/v1/assuranceEvents,
    get /dna/data/api/v1/assuranceEvents/{id},
"""

EXAMPLES = r"""
---
- name: Get all Assurance Events
  cisco.dnac.assurance_events_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceFamily: string
    startTime: 0
    endTime: 0
    messageType: string
    severity: 0
    siteId: string
    siteHierarchyId: string
    networkDeviceName: string
    networkDeviceId: string
    apMac: string
    clientMac: string
    attribute: string
    view: string
    offset: 0
    limit: 0
    sortBy: string
    order: string
  register: result
- name: Get Assurance Events by id
  cisco.dnac.assurance_events_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    attribute: string
    view: string
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
        "oldRadioChannelWidth": "string",
        "clientMac": "string",
        "switchNumber": "string",
        "assocRssi": 0,
        "affectedClients": [
          "string"
        ],
        "isPrivateMac": true,
        "frequency": "string",
        "apRole": "string",
        "replacingDeviceSerialNumber": "string",
        "messageType": "string",
        "failureCategory": "string",
        "apSwitchName": "string",
        "apSwitchId": "string",
        "radioChannelUtilization": "string",
        "mnemonic": "string",
        "radioChannelSlot": 0,
        "details": "string",
        "id": "string",
        "lastApDisconnectReason": "string",
        "networkDeviceName": "string",
        "identifier": "string",
        "reasonDescription": "string",
        "vlanId": "string",
        "udnId": "string",
        "auditSessionId": "string",
        "apMac": "string",
        "deviceFamily": "string",
        "radioNoise": "string",
        "wlcName": "string",
        "apRadioOperationState": "string",
        "name": "string",
        "failureIpAddress": "string",
        "newRadioChannelList": "string",
        "duid": "string",
        "roamType": "string",
        "candidateAPs": [
          {
            "apId": "string",
            "apName": "string",
            "apMac": "string",
            "bssid": "string",
            "rssi": 0
          }
        ],
        "replacedDeviceSerialNumber": "string",
        "oldRadioChannelList": "string",
        "ssid": "string",
        "subReasonDescription": "string",
        "wirelessClientEventEndTime": 0,
        "ipv4": "string",
        "wlcId": "string",
        "ipv6": "string",
        "missingResponseAPs": [
          {
            "apId": "string",
            "apName": "string",
            "apMac": "string",
            "bssid": "string",
            "type": "string",
            "frameType": "string"
          }
        ],
        "timestamp": 0,
        "severity": 0,
        "currentRadioPowerLevel": 0,
        "newRadioChannelWidth": "string",
        "assocSnr": 0,
        "authServerIp": "string",
        "childEvents": [
          {
            "id": "string",
            "name": "string",
            "timestamp": 0,
            "wirelessEventType": 0,
            "details": "string",
            "reasonCode": "string",
            "reasonDescription": "string",
            "subReasonCode": "string",
            "subReasonDescription": "string",
            "resultStatus": "string",
            "failureCategory": "string"
          }
        ],
        "connectedInterfaceName": "string",
        "dhcpServerIp": "string",
        "managementIpAddress": "string",
        "previousRadioPowerLevel": 0,
        "resultStatus": "string",
        "radioInterference": "string",
        "networkDeviceId": "string",
        "siteHierarchy": "string",
        "eventStatus": "string",
        "wirelessClientEventStartTime": 0,
        "siteHierarchyId": "string",
        "udnName": "string",
        "facility": "string",
        "lastApResetType": "string",
        "invalidIeAPs": [
          {
            "apId": "string",
            "apName": "string",
            "apMac": "string",
            "bssid": "string",
            "type": "string",
            "frameType": "string",
            "ies": "string"
          }
        ],
        "username": "string"
      },
      "version": "string"
    }
"""
