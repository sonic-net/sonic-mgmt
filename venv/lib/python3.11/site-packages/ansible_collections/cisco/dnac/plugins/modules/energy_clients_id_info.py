#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: energy_clients_id_info
short_description: Information module for Energy Clients
  Id
description:
  - Get Energy Clients Id by id. - > Retrieves client
    device energy data for a specified time range based
    on the client ID. For detailed information about
    the usage of the API, please refer to the Open API
    specification document - https //github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    deviceEnergy_1.0-1.0.1-resolved.yaml.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - >
        Id path parameter. Mac address of a client device
        (e.g., 54 9F C6 43 FF 80). It can be specified
        is any notational conventions 01 23 45 67 89
        AB or 01-23-45-67-89-AB or 0123.4567.89AB and
        is case insensitive.
    type: str
  startTime:
    description:
      - >
        StartTime query parameter. Start time from which
        API queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive. If `startTime` is not provided,
        API will default to one day before `endTime`.
    type: float
  endTime:
    description:
      - >
        EndTime query parameter. End time to which API
        queries the data set related to the resource.
        It must be specified in UNIX epochtime in milliseconds.
        Value is inclusive. If `endTime` is not provided,
        API will default to one day after `startTime`.
        If `startTime` is not provided either, API will
        default to current time.
    type: float
  view:
    description:
      - >
        View query parameter. List of views. View and
        attribute work in union. Each view will include
        its attributes. For example, view device includes
        all the attributes related to device. Please
        refer to `ClientDeviceEnergyView` model for
        supported list of views Examples `view=device&view=energy`.
    type: str
  attribute:
    description:
      - >
        Attribute query parameter. List of attributes.
        Please refer to `ClientDeviceEnergyAttribute`
        for supported list of attributes Examples `attribute=id&attribute=energyConsumed`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Clients
      GetClientEnergyByID
    description: Complete reference of the GetClientEnergyByID
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-client-energy-by-id
notes:
  - SDK Method used are
    clients.Clients.get_client_energy_by_id,
  - Paths used are
    get /dna/data/api/v1/energy/clients/{id},
"""

EXAMPLES = r"""
---
- name: Get Energy Clients Id by id
  cisco.dnac.energy_clients_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    startTime: 0
    endTime: 0
    view: string
    attribute: string
    id: string
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
        "id": "string",
        "deviceName": "string",
        "deviceCategory": "string",
        "deviceSubCategory": "string",
        "siteId": "string",
        "siteHierarchy": "string",
        "siteHierarchyId": "string",
        "energyConsumed": 0,
        "estimatedCost": 0,
        "estimatedEmission": 0,
        "carbonIntensity": 0,
        "connectedDeviceName": "string",
        "connectedInterfaceName": "string"
      },
      "version": "string"
    }
"""
