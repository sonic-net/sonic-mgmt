#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_ap_authorization_lists_id
short_description: Resource module for Wireless Settings
  Ap Authorization Lists Id
description:
  - Manage operations update and delete of the resource
    Wireless Settings Ap Authorization Lists Id.
  - This API allows the user to delete an AP Authorization
    List.
  - This API allows the user to update an AP Authorization
    List.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  apAuthorizationListName:
    description: AP Authorization List Name. For a AP
      Authorization List to be created successfully,
      either Local Authorization or Remote Authorization
      is mandatory.
    type: str
  id:
    description: Id path parameter. AP Authorization
      List ID.
    type: str
  localAuthorization:
    description: Wireless Settings Ap Authorization
      Lists Id's localAuthorization.
    suboptions:
      apMacEntries:
        description: List of Access Point's Ethernet
          MAC addresses. Allowed formats are 0a0b.0c01.0211,
          0a0b0c010211, 0a 0b 0c 01 02 11.
        elements: str
        type: list
      apSerialNumberEntries:
        description: List of Access Point's Serial Numbers.
        elements: str
        type: list
    type: dict
  remoteAuthorization:
    description: Wireless Settings Ap Authorization
      Lists Id's remoteAuthorization.
    suboptions:
      aaaServers:
        description: List of Authorization server IpAddresses.
          Obtain the AAA servers by using the API GET
          call '/dna/intent/api/v1/authentication-policy-servers'.
        elements: str
        type: list
      authorizeApWithMac:
        description: True if AP Authorization List should
          authorise APs With MAC addresses, else False.
          (For Non-Mesh Access Points, either of Authorize
          AP With MAC Address or Serial Number is required
          to be set to true).
        type: bool
      authorizeApWithSerialNumber:
        description: True if server IpAddresses are
          added and AP Authorization List should authorise
          APs With Serial Numbers, else False (For Non-Mesh
          Access Points, either of Authorize AP With
          MAC Address or Serial Number is required to
          be set to true).
        type: bool
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      DeleteAPAuthorizationList
    description: Complete reference of the DeleteAPAuthorizationList
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-ap-authorization-list
  - name: Cisco DNA Center documentation for Wireless
      UpdateAPAuthorizationList
    description: Complete reference of the UpdateAPAuthorizationList
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-ap-authorization-list
notes:
  - SDK Method used are
    wireless.Wireless.delete_ap_authorization_list,
    wireless.Wireless.update_ap_authorization_list,
  - Paths used are
    delete /dna/intent/api/v1/wirelessSettings/apAuthorizationLists/{id},
    put /dna/intent/api/v1/wirelessSettings/apAuthorizationLists/{id},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.wireless_settings_ap_authorization_lists_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
- name: Update by id
  cisco.dnac.wireless_settings_ap_authorization_lists_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    apAuthorizationListName: string
    id: string
    localAuthorization:
      apMacEntries:
        - string
      apSerialNumberEntries:
        - string
    remoteAuthorization:
      aaaServers:
        - string
      authorizeApWithMac: true
      authorizeApWithSerialNumber: true
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
