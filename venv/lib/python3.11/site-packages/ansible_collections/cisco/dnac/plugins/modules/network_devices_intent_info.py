#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_intent_info
short_description: Information module for Network Devices
  Intent
description:
  - Get all Network Devices Intent. - > API to fetch
    the list of network devices using basic filters.
    Use the `/dna/intent/api/v1/networkDevices/query`
    API for advanced filtering. Refer features for more
    details. The API returns a paginated response based
    on 'limit' and 'offset' parameters, allowing up
    to 500 records per page. 'limit' specifies the number
    of records, and 'offset' sets the starting point
    using 1-based indexing. Use /dna/intent/api/v1/networkDevices/count
    API to get the total record count. For data sets
    over 500 records, make multiple calls, adjusting
    'limit' and 'offset' to retrieve all records incrementally.
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
        statuses are MANAGED, UNDER_MAINTENANCE, NEVER_MANAGED.
        Refer features for more details.
    type: str
  views:
    description:
      - >
        Views query parameter. The specific views being
        requested. This is an optional parameter which
        can be passed to get one or more of the network
        device data. If this is not provided, then it
        will default to BASIC views. If multiple views
        are provided, the response will contain the
        union of the views. Refer features for more
        details. Available values BASIC, RESYNC, USER_DEFINED_FIELDS.
    type: str
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page. Min 1, Max 500.
    type: str
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: str
  sortBy:
    description:
      - >
        SortBy query parameter. A property within the
        response to sort by. Available values id, managementAddress,
        dnsResolvedManagementIpAddress, hostname, macAddress,
        type, family, series, platformids, softwareType,
        softwareVersion, vendor, bootTime, role, roleSource,
        apEthernetMacAddress, apManagerInterfaceIpAddress,
        apWlcIpAddress, deviceSupportLevel, reachabilityFailureReason,
        resyncStartTime, resyncEndTime, resyncReasons,
        pendingResyncRequestCount, pendingResyncRequestReasons,
        resyncIntervalSource, resyncIntervalMinutes.
    type: str
  order:
    description:
      - Order query parameter. Whether ascending or
        descending order should be used to sort the
        response.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      RetrieveNetworkDevices
    description: Complete reference of the RetrieveNetworkDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-network-devices
notes:
  - SDK Method used are
    devices.Devices.retrieve_network_devices,
  - Paths used are
    get /dna/intent/api/v1/networkDevices,
"""

EXAMPLES = r"""
---
- name: Get all Network Devices Intent
  cisco.dnac.network_devices_intent_info:
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
    views: string
    limit: string
    offset: string
    sortBy: string
    order: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "id": "string",
          "managementAddress": "string",
          "dnsResolvedManagementIpAddress": "string",
          "hostname": "string",
          "macAddress": "string",
          "serialNumbers": [
            "string"
          ],
          "type": "string",
          "family": "string",
          "series": "string",
          "status": "string",
          "platformIds": [
            "string"
          ],
          "softwareType": "string",
          "softwareVersion": "string",
          "vendor": "string",
          "stackDevice": true,
          "bootTime": 0,
          "role": "string",
          "roleSource": "string",
          "apEthernetMacAddress": "string",
          "apManagerInterfaceIpAddress": "string",
          "apWlcIpAddress": "string",
          "deviceSupportLevel": "string",
          "snmpLocation": "string",
          "snmpContact": "string",
          "reachabilityStatus": "string",
          "reachabilityFailureReason": "string",
          "managementState": "string",
          "lastSuccessfulResyncReasons": [
            "string"
          ],
          "resyncStartTime": 0,
          "resyncEndTime": 0,
          "resyncReasons": [
            "string"
          ],
          "resyncRequestedByApps": [
            "string"
          ],
          "pendingResyncRequestCount": 0,
          "pendingResyncRequestReasons": [
            "string"
          ],
          "resyncIntervalSource": "string",
          "resyncIntervalMinutes": 0,
          "errorCode": "string",
          "errorDescription": "string",
          "userDefinedFields": {}
        }
      ],
      "version": "string"
    }
"""
