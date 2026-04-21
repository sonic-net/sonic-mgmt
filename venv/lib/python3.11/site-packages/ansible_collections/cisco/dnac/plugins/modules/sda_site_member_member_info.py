#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_site_member_member_info
short_description: Information module for Sda Site Member
  Member
description:
  - Get all Sda Site Member Member.
  - API to get devices that are assigned to a site.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Site Id.
    type: str
  offset:
    description:
      - Offset query parameter. Offset/starting index
        for pagination.
    type: str
  limit:
    description:
      - Limit query parameter. Number of devices to
        be listed. Default and max supported value is
        500.
    type: str
  memberType:
    description:
      - MemberType query parameter. Member type (This
        API only supports the 'networkdevice' type).
    type: str
  level:
    description:
      - >
        Level query parameter. Depth of site hierarchy
        to be considered to list the devices. If the
        provided value is -1, devices for all child
        sites will be listed.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sites GetDevicesThatAreAssignedToASite
    description: Complete reference of the GetDevicesThatAreAssignedToASite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-devices-that-are-assigned-to-a-site
notes:
  - SDK Method used are
    sites.Sites.get_devices_that_are_assigned_to_a_site,
  - Paths used are
    get /dna/intent/api/v1/site-member/{id}/member,
"""

EXAMPLES = r"""
---
- name: Get all Sda Site Member Member
  cisco.dnac.sda_site_member_member_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    offset: string
    limit: string
    memberType: string
    level: string
    id: string
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
        "instanceUuid": "string",
        "instanceId": 0,
        "authEntityId": 0,
        "authEntityClass": 0,
        "instanceTenantId": "string",
        "deployPending": "string",
        "instanceVersion": 0,
        "apManagerInterfaceIp": "string",
        "associatedWlcIp": "string",
        "bootDateTime": "string",
        "collectionInterval": "string",
        "collectionIntervalValue": "string",
        "collectionStatus": "string",
        "description": "string",
        "deviceSupportLevel": "string",
        "dnsResolvedManagementAddress": "string",
        "family": "string",
        "hostname": "string",
        "interfaceCount": "string",
        "inventoryStatusDetail": "string",
        "lastUpdateTime": 0,
        "lastUpdated": "string",
        "lineCardCount": "string",
        "lineCardId": "string",
        "lastDeviceResyncStartTime": "string",
        "macAddress": "string",
        "managedAtleastOnce": true,
        "managementIpAddress": "string",
        "managementState": "string",
        "memorySize": "string",
        "paddedMgmtIpAddress": "string",
        "pendingSyncRequestsCount": "string",
        "platformId": "string",
        "reachabilityFailureReason": "string",
        "reachabilityStatus": "string",
        "reasonsForDeviceResync": "string",
        "reasonsForPendingSyncRequests": "string",
        "role": "string",
        "roleSource": "string",
        "serialNumber": "string",
        "series": "string",
        "snmpContact": "string",
        "snmpLocation": "string",
        "softwareType": "string",
        "softwareVersion": "string",
        "tagCount": "string",
        "type": "string",
        "upTime": "string",
        "uptimeSeconds": 0,
        "vendor": "string",
        "displayName": "string"
      }
    ]
"""
