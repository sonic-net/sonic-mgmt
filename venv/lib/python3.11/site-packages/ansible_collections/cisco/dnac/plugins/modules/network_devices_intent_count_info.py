#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_intent_count_info
short_description: Information module for Network Devices
  Intent Count
description:
  - Get all Network Devices Intent Count. - > API to
    fetch the count of network devices using basic filters.
    Use the `/dna/intent/api/v1/networkDevices/query/count`
    API if you need advanced filtering.
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
      - Id query parameter. Network device Id.
    type: str
  managementAddress:
    description:
      - ManagementAddress query parameter. Management
        address of the network device.
    type: str
  serialNumber:
    description:
      - SerialNumber query parameter. Serial number
        of the network device.
    type: str
  family:
    description:
      - Family query parameter. Product family of the
        network device. For example, Switches, Routers,
        etc.
    type: str
  stackDevice:
    description:
      - StackDevice query parameter. Flag indicating
        if the device is a stack device.
    type: str
  role:
    description:
      - >
        Role query parameter. Role assigned to the network
        device. Available values BORDER_ROUTER, CORE,
        DISTRIBUTION, ACCESS, UNKNOWN.
    type: str
  status:
    description:
      - >
        Status query parameter. Inventory related status
        of the network device. Available values MANAGED,
        SYNC_NOT_STARTED, SYNC_INIT_FAILED, SYNC_PRECHECK_FAILED,
        SYNC_IN_PROGRESS, SYNC_INTERNAL_ERROR, SYNC_DISABLED,
        DELETING_DEVICE, UNDER_MAINTENANCE, QUARANTINED,
        UNASSOCIATED, UNREACHABLE, UNKNOWN. Refer features
        for more details.
    type: str
  reachabilityStatus:
    description:
      - >
        ReachabilityStatus query parameter. Reachability
        status of the network device. Available values
        REACHABLE, ONLY_PING_REACHABLE, UNREACHABLE,
        UNKNOWN. Refer features for more details.
    type: str
  managementState:
    description:
      - >
        ManagementState query parameter. The status
        of the network device's manageability. Available
        values MANAGED, UNDER_MAINTENANCE, NEVER_MANAGED.
        Refer features for more details.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      CountTheNumberOfNetworkDevices
    description: Complete reference of the CountTheNumberOfNetworkDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!count-the-number-of-network-devices
notes:
  - SDK Method used are
    devices.Devices.count_the_number_of_network_devices,
  - Paths used are
    get /dna/intent/api/v1/networkDevices/count,
"""

EXAMPLES = r"""
---
- name: Get all Network Devices Intent Count
  cisco.dnac.network_devices_intent_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
    managementAddress: string
    serialNumber: string
    family: string
    stackDevice: string
    role: string
    status: string
    reachabilityStatus: string
    managementState: string
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
