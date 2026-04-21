#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ipam_server_setting
short_description: Resource module for Ipam Server Setting
description:
  - Manage operations create, update and delete of the
    resource Ipam Server Setting. - > Creates configuration
    details of the external IPAM server. You should
    only create one external IPAM server; delete any
    existing external server before creating a new one.
  - Deletes configuration details of the external IPAM
    server.
  - Updates configuration details of the external IPAM
    server.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  password:
    description: The password for the external IPAM
      server login username.
    type: str
  provider:
    description: Type of external IPAM. Can be either
      INFOBLOX, BLUECAT or GENERIC.
    type: str
  serverName:
    description: A descriptive name of this external
      server, used for identification purposes.
    type: str
  serverUrl:
    description: The URL of this external server.
    type: str
  syncView:
    description: Synchronize the IP pools from the local
      IPAM to this external server.
    type: bool
  userName:
    description: The external IPAM server login username.
    type: str
  view:
    description: The view under which pools are created
      in the external IPAM server.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for System
      Settings CreatesConfigurationDetailsOfTheExternalIPAMServer
    description: Complete reference of the CreatesConfigurationDetailsOfTheExternalIPAMServer
      API.
    link: https://developer.cisco.com/docs/dna-center/#!creates-configuration-details-of-the-external-ipam-server
  - name: Cisco DNA Center documentation for System
      Settings DeletesConfigurationDetailsOfTheExternalIPAMServer
    description: Complete reference of the DeletesConfigurationDetailsOfTheExternalIPAMServer
      API.
    link: https://developer.cisco.com/docs/dna-center/#!deletes-configuration-details-of-the-external-ipam-server
  - name: Cisco DNA Center documentation for System
      Settings UpdatesConfigurationDetailsOfTheExternalIPAMServer
    description: Complete reference of the UpdatesConfigurationDetailsOfTheExternalIPAMServer
      API.
    link: https://developer.cisco.com/docs/dna-center/#!updates-configuration-details-of-the-external-ipam-server
notes:
  - SDK Method used are
    system_settings.SystemSettings.creates_configuration_details_of_the_external_ip_a_m_server,
    system_settings.SystemSettings.deletes_configuration_details_of_the_external_ip_a_m_server,
    system_settings.SystemSettings.updates_configuration_details_of_the_external_ip_a_m_server,
  - Paths used are
    post /dna/intent/api/v1/ipam/serverSetting,
    delete /dna/intent/api/v1/ipam/serverSetting,
    put
    /dna/intent/api/v1/ipam/serverSetting,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.ipam_server_setting:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    password: string
    provider: string
    serverName: string
    serverUrl: string
    syncView: true
    userName: string
    view: string
- name: Delete all
  cisco.dnac.ipam_server_setting:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
- name: Update all
  cisco.dnac.ipam_server_setting:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    password: string
    serverName: string
    serverUrl: string
    syncView: true
    userName: string
    view: string
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
