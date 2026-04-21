#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_sm_devices_info
short_description: Information module for networks _sm _devices
description:
  - Get all networks _sm _devices.
  - List the devices enrolled in an SM network with various specified fields and filters.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
  - cisco.meraki.module_info_pagination
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  networkId:
    description:
      - NetworkId path parameter. Network ID.
    type: str
  fields:
    description:
      - >
        Fields query parameter. Additional fields that will be displayed for each device. The default fields are id, name, tags, ssid, wifiMac,
        osName, systemModel, uuid, and serialNumber. The additional fields are ip, systemType, availableDeviceCapacity, kioskAppName, biosVersion,
        lastConnected, missingAppsCount, userSuppliedAddress, location, lastUser, ownerEmail, ownerUsername, osBuild, publicIp, phoneNumber, diskInfoJson,
        deviceCapacity, isManaged, hadMdm, isSupervised, meid, imei, iccid, simCarrierNetwork, cellularDataUsed, isHotspotEnabled, createdAt,
        batteryEstCharge, quarantined, avName, avRunning, asName, fwName, isRooted, loginRequired, screenLockEnabled, screenLockDelay, autoLoginDisabled,
        autoTags, hasMdm, hasDesktopAgent, diskEncryptionEnabled, hardwareEncryptionCaps, passCodeLock, usesHardwareKeystore, androidSecurityPatchVersion,
        cellular, and url.
    elements: str
    type: list
  wifiMacs:
    description:
      - WifiMacs query parameter. Filter devices by wifi mac(s).
    elements: str
    type: list
  serials:
    description:
      - Serials query parameter. Filter devices by serial(s).
    elements: str
    type: list
  ids:
    description:
      - Ids query parameter. Filter devices by id(s).
    elements: str
    type: list
  uuids:
    description:
      - Uuids query parameter. Filter devices by uuid(s).
    elements: str
    type: list
  systemTypes:
    description:
      - SystemTypes query parameter. Filter devices by system type(s).
    elements: str
    type: list
  scope:
    description:
      - >
        Scope query parameter. Specify a scope (one of all, none, withAny, withAll, withoutAny, or withoutAll) and a set of tags.
    elements: str
    type: list
  perPage:
    description:
      - PerPage query parameter. The number of entries per page returned. Acceptable range is 3 - 1000. Default is 1000.
    type: int
  startingAfter:
    description:
      - >
        StartingAfter query parameter. A token used by the server to indicate the start of the page. Often this is a timestamp or an ID but it
        is not limited to those. This parameter should not be defined by client applications. The link for the first, last, prev, or next page
        in the HTTP Link header should define it.
    type: str
  endingBefore:
    description:
      - >
        EndingBefore query parameter. A token used by the server to indicate the end of the page. Often this is a timestamp or an ID but it is
        not limited to those. This parameter should not be defined by client applications. The link for the first, last, prev, or next page in
        the HTTP Link header should define it.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for sm getNetworkSmDevices
    description: Complete reference of the getNetworkSmDevices API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-sm-devices
notes:
  - SDK Method used are
    sm.Sm.get_network_sm_devices,
  - Paths used are
    get /networks/{networkId}/sm/devices,
"""

EXAMPLES = r"""
- name: Get all networks _sm _devices
  cisco.meraki.networks_sm_devices_info:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    fields: []
    wifiMacs: []
    serials: []
    ids: []
    uuids: []
    systemTypes: []
    scope: []
    perPage: 0
    startingAfter: string
    endingBefore: string
    networkId: string
    total_pages: -1
    direction: next
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "id": "string",
        "ip": "string",
        "name": "string",
        "notes": "string",
        "osName": "string",
        "serial": "string",
        "serialNumber": "string",
        "ssid": "string",
        "systemModel": "string",
        "tags": [
          "string"
        ],
        "uuid": "string",
        "wifiMac": "string"
      }
    ]
"""
