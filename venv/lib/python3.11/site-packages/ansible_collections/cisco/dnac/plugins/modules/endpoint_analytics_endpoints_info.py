#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: endpoint_analytics_endpoints_info
short_description: Information module for Endpoint Analytics
  Endpoints
description:
  - Get all Endpoint Analytics Endpoints.
  - Get Endpoint Analytics Endpoints by id.
  - Fetches details of the endpoint for the given unique
    identifier 'epId'. - > Query the endpoints, optionally
    using various filter and pagination criteria. 'GET
    /endpoints/count' API can be used to find out the
    total number of endpoints matching the filter criteria.
version_added: '6.16.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  profilingStatus:
    description:
      - >
        ProfilingStatus query parameter. Profiling status
        of the endpoint. Possible values are 'profiled',
        'partialProfiled', 'notProfiled'.
    type: str
  macAddress:
    description:
      - MacAddress query parameter. MAC address to search
        for. Partial string is allowed.
    type: str
  macAddresses:
    description:
      - MacAddresses query parameter. List of MAC addresses
        to filter on. Only exact matches will be returned.
    elements: str
    type: list
  ip:
    description:
      - Ip query parameter. IP address to search for.
        Partial string is allowed.
    type: str
  deviceType:
    description:
      - DeviceType query parameter. Type of device to
        search for. Partial string is allowed.
    type: str
  hardwareManufacturer:
    description:
      - HardwareManufacturer query parameter. Hardware
        manufacturer to search for. Partial string is
        allowed.
    type: str
  hardwareModel:
    description:
      - HardwareModel query parameter. Hardware model
        to search for. Partial string is allowed.
    type: str
  operatingSystem:
    description:
      - OperatingSystem query parameter. Operating system
        to search for. Partial string is allowed.
    type: str
  registered:
    description:
      - Registered query parameter. Flag to fetch manually
        registered or non-registered endpoints.
    type: bool
  randomMac:
    description:
      - RandomMac query parameter. Flag to fetch endpoints
        having randomized MAC or not.
    type: bool
  trustScore:
    description:
      - >
        TrustScore query parameter. Overall trust score
        of the endpoint. It can be provided either as
        a number value (e.g. 5), or as a range (e.g.
        3-7). Provide value as '-' if you want to search
        for all endpoints where trust score is not assigned.
    type: str
  authMethod:
    description:
      - AuthMethod query parameter. Authentication method.
        Partial string is allowed.
    type: str
  postureStatus:
    description:
      - PostureStatus query parameter. Posture status.
    type: str
  aiSpoofingTrustLevel:
    description:
      - >
        AiSpoofingTrustLevel query parameter. Trust
        level of the endpoint due to AI spoofing. Possible
        values are 'low', 'medium', 'high'.
    type: str
  changedProfileTrustLevel:
    description:
      - >
        ChangedProfileTrustLevel query parameter. Trust
        level of the endpoint due to changing profile
        labels. Possible values are 'low', 'medium',
        'high'.
    type: str
  natTrustLevel:
    description:
      - >
        NatTrustLevel query parameter. Trust level of
        the endpoint due to NAT access. Possible values
        are 'low', 'medium', 'high'.
    type: str
  concurrentMacTrustLevel:
    description:
      - >
        ConcurrentMacTrustLevel query parameter. Trust
        level of the endpoint due to concurrent MAC
        address. Possible values are 'low', 'medium',
        'high'.
    type: str
  ipBlocklistDetected:
    description:
      - IpBlocklistDetected query parameter. Flag to
        fetch endpoints hitting IP blocklist or not.
    type: bool
  unauthPortDetected:
    description:
      - UnauthPortDetected query parameter. Flag to
        fetch endpoints exposing unauthorized ports
        or not.
    type: bool
  weakCredDetected:
    description:
      - WeakCredDetected query parameter. Flag to fetch
        endpoints having weak credentials or not.
    type: bool
  ancPolicy:
    description:
      - AncPolicy query parameter. ANC policy. Only
        exact match will be returned.
    type: str
  limit:
    description:
      - >
        Limit query parameter. Maximum number of records
        to be fetched. If not provided, 50 records will
        be fetched by default. Maximum 1000 records
        can be fetched at a time. Use pagination if
        more records need to be fetched.
    type: int
  offset:
    description:
      - Offset query parameter. Record offset to start
        data fetch at. Offset starts at zero.
    type: int
  sortBy:
    description:
      - >
        SortBy query parameter. Name of the column to
        sort the results on. Please note that fetch
        might take more time if sorting is requested.
        Possible values are 'macAddress', 'ip'.
    type: str
  order:
    description:
      - Order query parameter. Order to be used for
        sorting. Possible values are 'asc', 'desc'.
    type: str
  include:
    description:
      - >
        Include query parameter. The datasets that should
        be included in the response. By default, value
        of this parameter is blank, and the response
        will include only basic details of the endpoint.
        To include other datasets or dictionaries, send
        comma separated list of following values 'ALL'
        - Include all attributes. 'CDP', 'DHCP', etc.
        - Include attributes from given dictionaries.
        To get full list of dictionaries, use corresponding
        GET API. 'ANC' - Include ANC policy related
        details. 'TRUST' - Include trust score details.
    type: str
  epId:
    description:
      - EpId path parameter. Unique identifier for the
        endpoint.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for AI Endpoint
      Analytics GetEndpointDetails
    description: Complete reference of the GetEndpointDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-endpoint-details
  - name: Cisco DNA Center documentation for AI Endpoint
      Analytics QueryTheEndpoints
    description: Complete reference of the QueryTheEndpoints
      API.
    link: https://developer.cisco.com/docs/dna-center/#!query-the-endpoints
notes:
  - SDK Method used are
    ai_endpoint_analytics.AiEndpointAnalytics.get_endpoint_details,
    ai_endpoint_analytics.AiEndpointAnalytics.query_the_endpoints,
  - Paths used are
    get /dna/intent/api/v1/endpoint-analytics/endpoints,
    get /dna/intent/api/v1/endpoint-analytics/endpoints/{epId},
"""

EXAMPLES = r"""
---
- name: Get all Endpoint Analytics Endpoints
  cisco.dnac.endpoint_analytics_endpoints_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    profilingStatus: string
    macAddress: string
    macAddresses: []
    ip: string
    deviceType: string
    hardwareManufacturer: string
    hardwareModel: string
    operatingSystem: string
    registered: true
    randomMac: true
    trustScore: string
    authMethod: string
    postureStatus: string
    aiSpoofingTrustLevel: string
    changedProfileTrustLevel: string
    natTrustLevel: string
    concurrentMacTrustLevel: string
    ipBlocklistDetected: true
    unauthPortDetected: true
    weakCredDetected: true
    ancPolicy: string
    limit: 0
    offset: 0
    sortBy: string
    order: string
    include: string
  register: result
- name: Get Endpoint Analytics Endpoints by id
  cisco.dnac.endpoint_analytics_endpoints_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    include: string
    epId: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "duid": "string",
      "macAddress": "string",
      "deviceType": [
        "string"
      ],
      "hardwareManufacturer": [
        "string"
      ],
      "hardwareModel": [
        "string"
      ],
      "operatingSystem": [
        "string"
      ],
      "lastProbeCollectionTimestamp": 0,
      "randomMac": true,
      "registered": true,
      "attributes": {},
      "trustData": {
        "trustScore": 0,
        "authMethod": "string",
        "postureStatus": "string",
        "aiSpoofingTrustLevel": "string",
        "changedProfileTrustLevel": "string",
        "natTrustLevel": "string",
        "concurrentMacTrustLevel": "string",
        "ipBlocklistDetected": true,
        "unauthPortDetected": true,
        "weakCredDetected": true
      },
      "ancPolicy": "string",
      "granularAncPolicy": [
        {
          "name": "string",
          "nasIpAddress": "string"
        }
      ]
    }
"""
