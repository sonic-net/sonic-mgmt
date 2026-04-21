#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: global_pool
short_description: Resource module for Global Pool
description:
  - Manage operations create, update and delete of the
    resource Global Pool.
  - API to create global pool. There is a limit of creating
    25 global pools per request.
  - API to delete global IP pool.
  - API to update global pool. There is a limit of updating
    25 global pools per request.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Global pool id.
    type: str
  settings:
    description: Global Pool's settings.
    suboptions:
      ippool:
        description: Global Pool's ippool.
        elements: dict
        suboptions:
          dhcpServerIps:
            description: Dhcp Server Ips.
            elements: str
            type: list
          dnsServerIps:
            description: Dns Server Ips.
            elements: str
            type: list
          gateway:
            description: Gateway.
            type: str
          id:
            description: Id.
            type: str
          ipPoolName:
            description: Ip Pool Name.
            type: str
        type: list
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings CreateGlobalPool
    description: Complete reference of the CreateGlobalPool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-global-pool
  - name: Cisco DNA Center documentation for Network
      Settings DeleteGlobalIPPool
    description: Complete reference of the DeleteGlobalIPPool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-global-ip-pool
  - name: Cisco DNA Center documentation for Network
      Settings UpdateGlobalPool
    description: Complete reference of the UpdateGlobalPool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-global-pool
notes:
  - SDK Method used are
    network_settings.NetworkSettings.create_global_pool,
    network_settings.NetworkSettings.delete_global_ip_pool,
    network_settings.NetworkSettings.update_global_pool,
  - Paths used are
    post /dna/intent/api/v1/global-pool,
    delete /dna/intent/api/v1/global-pool/{id},
    put
    /dna/intent/api/v1/global-pool,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.global_pool:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    settings:
      ippool:
        - dhcpServerIps:
            - string
          dnsServerIps:
            - string
          gateway: string
          id: string
          ipPoolName: string
- name: Create
  cisco.dnac.global_pool:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    settings:
      ippool:
        - IpAddressSpace: string
          dhcpServerIps:
            - string
          dnsServerIps:
            - string
          gateway: string
          ipPoolCidr: string
          ipPoolName: string
          type: string
- name: Delete by id
  cisco.dnac.global_pool:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
"""
