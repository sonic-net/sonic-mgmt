#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: qos_device_interface
short_description: Resource module for Qos Device Interface
description:
  - Manage operations create, update and delete of the
    resource Qos Device Interface. - > Create qos device
    interface infos associate with network device id
    to allow the user to mark specific interfaces as
    WAN, to associate WAN interfaces with specific SP
    Profile and to be able to define a shaper on WAN
    interfaces.
  - Delete all qos device interface infos associate
    with network device id.
  - Update existing qos device interface infos associate
    with network device id.
version_added: '4.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Id of the qos device
      info, this object holds all qos device interface
      infos associate with network device id.
    type: str
  payload:
    description: Qos Device Interface's payload.
    elements: dict
    suboptions:
      excludedInterfaces:
        description: Excluded interfaces ids.
        elements: str
        type: list
      id:
        description: Id of Qos device info.
        type: str
      name:
        description: Device name.
        type: str
      networkDeviceId:
        description: Network device id.
        type: str
      qosDeviceInterfaceInfo:
        description: Qos Device Interface's qosDeviceInterfaceInfo.
        elements: dict
        suboptions:
          dmvpnRemoteSitesBw:
            description: Dmvpn remote sites bandwidth.
            elements: int
            type: list
          instanceId:
            description: Instance id.
            type: int
          interfaceId:
            description: Interface id.
            type: str
          interfaceName:
            description: Interface name.
            type: str
          label:
            description: SP Profile name.
            type: str
          role:
            description: Interface role.
            type: str
          uploadBW:
            description: Upload bandwidth.
            type: int
        type: list
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy CreateQosDeviceInterfaceInfo
    description: Complete reference of the CreateQosDeviceInterfaceInfo
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-qos-device-interface-info
  - name: Cisco DNA Center documentation for Application
      Policy DeleteQosDeviceInterfaceInfo
    description: Complete reference of the DeleteQosDeviceInterfaceInfo
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-qos-device-interface-info
  - name: Cisco DNA Center documentation for Application
      Policy UpdateQosDeviceInterfaceInfo
    description: Complete reference of the UpdateQosDeviceInterfaceInfo
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-qos-device-interface-info
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.create_qos_device_interface_info,
    application_policy.ApplicationPolicy.delete_qos_device_interface_info,
    application_policy.ApplicationPolicy.update_qos_device_interface_info,
  - Paths used are
    post /dna/intent/api/v1/qos-device-interface-info,
    delete /dna/intent/api/v1/qos-device-interface-info/{id},
    put /dna/intent/api/v1/qos-device-interface-info,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.qos_device_interface:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - excludedInterfaces:
          - string
        id: string
        name: string
        networkDeviceId: string
        qosDeviceInterfaceInfo:
          - dmvpnRemoteSitesBw:
              - 0
            instanceId: 0
            interfaceId: string
            interfaceName: string
            label: string
            role: string
            uploadBW: 0
- name: Create
  cisco.dnac.qos_device_interface:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - excludedInterfaces:
          - string
        name: string
        networkDeviceId: string
        qosDeviceInterfaceInfo:
          - dmvpnRemoteSitesBw:
              - 0
            interfaceId: string
            interfaceName: string
            label: string
            role: string
            uploadBW: 0
- name: Delete by id
  cisco.dnac.qos_device_interface:
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
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
