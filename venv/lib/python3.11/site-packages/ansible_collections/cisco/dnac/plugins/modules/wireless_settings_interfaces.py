#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_interfaces
short_description: Resource module for Wireless Settings
  Interfaces
description:
  - Manage operations create, update and delete of the
    resource Wireless Settings Interfaces.
  - This API allows the user to create an interface.
  - This API allows the user to delete an interface
    by ID.
  - This API allows the user to update an interface
    by ID.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Interface ID.
    type: str
  interfaceName:
    description: Interface Name.
    type: str
  vlanId:
    description: VLAN ID range is 1-4094.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      CreateInterface
    description: Complete reference of the CreateInterface
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-interface
  - name: Cisco DNA Center documentation for Wireless
      DeleteInterface
    description: Complete reference of the DeleteInterface
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-interface
  - name: Cisco DNA Center documentation for Wireless
      UpdateInterface
    description: Complete reference of the UpdateInterface
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-interface
notes:
  - SDK Method used are
    wireless.Wireless.create_interface,
    wireless.Wireless.delete_interface,
    wireless.Wireless.update_interface,
  - Paths used are
    post /dna/intent/api/v1/wirelessSettings/interfaces,
    delete /dna/intent/api/v1/wirelessSettings/interfaces/{id},
    put /dna/intent/api/v1/wirelessSettings/interfaces/{id},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wireless_settings_interfaces:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    interfaceName: string
    vlanId: 0
- name: Delete by id
  cisco.dnac.wireless_settings_interfaces:
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
  cisco.dnac.wireless_settings_interfaces:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    id: string
    interfaceName: string
    vlanId: 0
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
