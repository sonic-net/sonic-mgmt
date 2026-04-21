#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: endpoint_analytics_endpoints_count_info
short_description: Information module for Endpoint Analytics
  Endpoints Count
description:
  - Get all Endpoint Analytics Endpoints Count.
  - Fetch the total count of endpoints that match the
    given filter criteria.
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for AI Endpoint
      Analytics FetchTheCountOfEndpoints
    description: Complete reference of the FetchTheCountOfEndpoints
      API.
    link: https://developer.cisco.com/docs/dna-center/#!fetch-the-count-of-endpoints
notes:
  - SDK Method used are
    ai_endpoint_analytics.AiEndpointAnalytics.fetch_the_count_of_endpoints,
  - Paths used are
    get /dna/intent/api/v1/endpoint-analytics/endpoints/count,
"""

EXAMPLES = r"""
---
- name: Get all Endpoint Analytics Endpoints Count
  cisco.dnac.endpoint_analytics_endpoints_count_info:
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
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "count": 0
    }
"""
