#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: applications_health_info
short_description: Information module for Applications
  Health
description:
  - Get all Applications Health. - > Intent API to get
    a list of applications for a specific site, a device,
    or a client device's MAC address. For a combination
    of a specific application with site and/or device
    the API gets list of issues/devices/endpoints.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description:
      - SiteId query parameter. Assurance site UUID
        value (Cannot be submitted together with deviceId
        and clientMac).
    type: str
  deviceId:
    description:
      - DeviceId query parameter. Assurance device UUID
        value (Cannot be submitted together with siteId
        and clientMac).
    type: str
  macAddress:
    description:
      - MacAddress query parameter. Client device's
        MAC address (Cannot be submitted together with
        siteId and deviceId).
    type: str
  startTime:
    description:
      - StartTime query parameter. Starting epoch time
        in milliseconds of time window.
    type: float
  endTime:
    description:
      - EndTime query parameter. Ending epoch time in
        milliseconds of time window.
    type: float
  applicationHealth:
    description:
      - >
        ApplicationHealth query parameter. Application
        health category (POOR, FAIR, or GOOD. Optionally
        use with siteId only).
    type: str
  offset:
    description:
      - >
        Offset query parameter. The offset of the first
        application in the returned data (optionally
        used with siteId only).
    type: int
  limit:
    description:
      - >
        Limit query parameter. The max number of application
        entries in returned data 1, 1000 (optionally
        used with siteId only).
    type: int
  applicationName:
    description:
      - ApplicationName query parameter. The name of
        the application to get information on.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Applications
      Applications
    description: Complete reference of the Applications
      API.
    link: https://developer.cisco.com/docs/dna-center/#!applications-applications
notes:
  - SDK Method used are
    applications.Applications.applications,
  - Paths used are
    get /dna/intent/api/v1/application-health,
"""

EXAMPLES = r"""
---
- name: Get all Applications Health
  cisco.dnac.applications_health_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
    deviceId: string
    macAddress: string
    startTime: 0
    endTime: 0
    applicationHealth: string
    offset: 0
    limit: 0
    applicationName: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "totalCount": 0,
      "response": [
        {
          "name": "string",
          "health": 0,
          "businessRelevance": "string",
          "trafficClass": "string",
          "usageBytes": 0,
          "averageThroughput": 0,
          "packetLossPercent": {},
          "networkLatency": {},
          "jitter": {},
          "applicationServerLatency": {},
          "clientNetworkLatency": {},
          "serverNetworkLatency": {},
          "exporterIpAddress": "string",
          "exporterName": "string",
          "exporterUUID": "string",
          "exporterFamily": "string",
          "clientName": "string",
          "clientIp": "string",
          "location": "string",
          "operatingSystem": "string",
          "deviceType": "string",
          "clientMacAddress": "string",
          "issueId": "string",
          "issueName": "string",
          "application": "string",
          "severity": "string",
          "summary": "string",
          "rootCause": "string",
          "timestamp": 0,
          "occurrences": 0,
          "priority": "string"
        }
      ]
    }
"""
