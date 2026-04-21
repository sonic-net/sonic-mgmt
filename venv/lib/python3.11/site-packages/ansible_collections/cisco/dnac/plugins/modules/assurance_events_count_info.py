#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: assurance_events_count_info
short_description: Information module for Assurance
  Events Count
description:
  - Get all Assurance Events Count. - > API to fetch
    the count of assurance events that match the filter
    criteria. Please refer to the 'API Support Documentation'
    section to understand which fields are supported.
    For detailed information about the usage of the
    API, please refer to the Open API specification
    document - https //github.com/cisco-en- programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
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
    type: str
  endTime:
    description:
      - >
        EndTime query parameter. End time to which API
        queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive. If `endTime` is not provided,
        API will default to current time.
    type: str
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
    type: str
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
        requested).
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      CountTheNumberOfEvents
    description: Complete reference of the CountTheNumberOfEvents
      API.
    link: https://developer.cisco.com/docs/dna-center/#!count-the-number-of-events
notes:
  - SDK Method used are
    devices.Devices.count_the_number_of_events,
  - Paths used are
    get /dna/data/api/v1/assuranceEvents/count,
"""

EXAMPLES = r"""
---
- name: Get all Assurance Events Count
  cisco.dnac.assurance_events_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceFamily: string
    startTime: string
    endTime: string
    messageType: string
    severity: string
    siteId: string
    siteHierarchyId: string
    networkDeviceName: string
    networkDeviceId: string
    apMac: string
    clientMac: string
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
