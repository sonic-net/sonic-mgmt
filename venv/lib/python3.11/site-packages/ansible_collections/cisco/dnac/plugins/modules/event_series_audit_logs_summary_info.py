#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: event_series_audit_logs_summary_info
short_description: Information module for Event Series
  Audit Logs Summary
description:
  - Get all Event Series Audit Logs Summary.
  - Get Audit Log Summary from the Event-Hub.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  parentInstanceId:
    description:
      - ParentInstanceId query parameter. Parent Audit
        Log record's instanceID.
    type: str
  isParentOnly:
    description:
      - IsParentOnly query parameter. Parameter to filter
        parent only audit-logs.
    type: bool
  instanceId:
    description:
      - InstanceId query parameter. InstanceID of the
        Audit Log.
    type: str
  name:
    description:
      - Name query parameter. Audit Log notification
        event name.
    type: str
  eventId:
    description:
      - EventId query parameter. Audit Log notification's
        event ID.
    type: str
  category:
    description:
      - >
        Category query parameter. Audit Log notification's
        event category. Supported values INFO, WARN,
        ERROR, ALERT, TASK_PROGRESS, TASK_FAILURE, TASK_COMPLETE,
        COMMAND, QUERY, CONVERSATION.
    type: str
  severity:
    description:
      - Severity query parameter. Audit Log notification's
        event severity. Supported values 1, 2, 3, 4,
        5.
    type: str
  domain:
    description:
      - Domain query parameter. Audit Log notification's
        event domain.
    type: str
  subDomain:
    description:
      - SubDomain query parameter. Audit Log notification's
        event sub-domain.
    type: str
  source:
    description:
      - Source query parameter. Audit Log notification's
        event source.
    type: str
  userId:
    description:
      - UserId query parameter. Audit Log notification's
        event userId.
    type: str
  context:
    description:
      - Context query parameter. Audit Log notification's
        event correlationId.
    type: str
  eventHierarchy:
    description:
      - >
        EventHierarchy query parameter. Audit Log notification's
        event eventHierarchy. Example "US.CA.San Jose"
        OR "US.CA" OR "CA.San Jose" - Delimiter for
        hierarchy separation is ".".
    type: str
  siteId:
    description:
      - SiteId query parameter. Audit Log notification's
        siteId.
    type: str
  deviceId:
    description:
      - DeviceId query parameter. Audit Log notification's
        deviceId.
    type: str
  isSystemEvents:
    description:
      - IsSystemEvents query parameter. Parameter to
        filter system generated audit-logs.
    type: bool
  description:
    description:
      - >
        Description query parameter. String full/partial
        search - (Provided input string is case insensitively
        matched for records).
    type: str
  startTime:
    description:
      - >
        StartTime query parameter. Start Time in milliseconds
        since Epoch Eg. 1597950637211 (when provided
        endTime is mandatory).
    type: float
  endTime:
    description:
      - >
        EndTime query parameter. End Time in milliseconds
        since Epoch Eg. 1597961437211 (when provided
        startTime is mandatory).
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Event Management
      GetAuditLogSummary
    description: Complete reference of the GetAuditLogSummary
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-audit-log-summary
notes:
  - SDK Method used are
    event_management.EventManagement.get_audit_log_summary,
  - Paths used are
    get /dna/data/api/v1/event/event-series/audit-log/summary,
"""

EXAMPLES = r"""
---
- name: Get all Event Series Audit Logs Summary
  cisco.dnac.event_series_audit_logs_summary_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    parentInstanceId: string
    isParentOnly: true
    instanceId: string
    name: string
    eventId: string
    category: string
    severity: string
    domain: string
    subDomain: string
    source: string
    userId: string
    context: string
    eventHierarchy: string
    siteId: string
    deviceId: string
    isSystemEvents: true
    description: string
    startTime: 0
    endTime: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "count": 0,
        "maxTimestamp": 0,
        "minTimestamp": 0
      }
    ]
"""
