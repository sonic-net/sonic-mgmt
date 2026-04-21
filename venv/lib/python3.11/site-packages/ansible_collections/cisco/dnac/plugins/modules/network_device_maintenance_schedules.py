#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_maintenance_schedules
short_description: Resource module for Network Device
  Maintenance Schedules
description:
  - Manage operation create of the resource Network
    Device Maintenance Schedules. - > API to create
    maintenance schedule for network devices. The state
    of network device can be queried using API `GET
    /dna/intent/api/v1/networkDevices`. The `managementState`
    attribute of the network device will be updated
    to `UNDER_MAINTENANCE` when the maintenance window
    starts.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  description:
    description: A brief narrative describing the maintenance
      schedule.
    type: str
  maintenanceSchedule:
    description: Network Device Maintenance Schedules's
      maintenanceSchedule.
    suboptions:
      endTime:
        description: End time indicates the ending of
          the maintenance window in Unix epoch time
          in milliseconds.
        type: float
      recurrence:
        description: Network Device Maintenance Schedules's
          recurrence.
        suboptions:
          interval:
            description: Interval for recurrence in
              days. The interval must be longer than
              the duration of the schedules. The maximum
              allowed interval is 365 days.
            type: int
          recurrenceEndTime:
            description: The end date for the recurrence
              in Unix epoch time in milliseconds. Recurrence
              end time should be greater than maintenance
              end date/time.
            type: float
        type: dict
      startTime:
        description: Start time indicates the beginning
          of the maintenance window in Unix epoch time
          in milliseconds.
        type: float
    type: dict
  networkDeviceIds:
    description: List of network device ids. This field
      is applicable only during creation of schedules;
      for updates, it is read-only.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      CreateMaintenanceScheduleForNetworkDevices
    description: Complete reference of the CreateMaintenanceScheduleForNetworkDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-maintenance-schedule-for-network-devices
notes:
  - SDK Method used are
    devices.Devices.create_maintenance_schedule_for_network_devices,
  - Paths used are
    post /dna/intent/api/v1/networkDeviceMaintenanceSchedules,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_device_maintenance_schedules:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    description: string
    maintenanceSchedule:
      endTime: 0
      recurrence:
        interval: 0
        recurrenceEndTime: 0
      startTime: 0
    networkDeviceIds:
      - string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
