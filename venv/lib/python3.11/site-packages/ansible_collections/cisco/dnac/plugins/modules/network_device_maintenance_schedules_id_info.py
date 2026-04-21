#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_maintenance_schedules_id_info
short_description: Information module for Network Device
  Maintenance Schedules Id
description:
  - Get Network Device Maintenance Schedules Id by id.
  - API to retrieve the maintenance schedule information
    for the given id.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Unique identifier for the
        maintenance schedule.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      RetrievesTheMaintenanceScheduleInformation
    description: Complete reference of the RetrievesTheMaintenanceScheduleInformation
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-maintenance-schedule-information
notes:
  - SDK Method used are
    devices.Devices.retrieves_the_maintenance_schedule_information,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceMaintenanceSchedules/{id},
"""

EXAMPLES = r"""
---
- name: Get Network Device Maintenance Schedules Id
    by id
  cisco.dnac.network_device_maintenance_schedules_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
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
        "description": "string",
        "maintenanceSchedule": {
          "startId": "string",
          "endId": "string",
          "startTime": 0,
          "endTime": 0,
          "recurrence": {
            "interval": 0,
            "recurrenceEndTime": 0
          },
          "status": "string"
        },
        "networkDeviceIds": [
          "string"
        ]
      },
      "version": "string"
    }
"""
