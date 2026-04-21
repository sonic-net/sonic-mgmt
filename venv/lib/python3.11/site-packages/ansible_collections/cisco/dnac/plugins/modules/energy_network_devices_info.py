#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: energy_network_devices_info
short_description: Information module for Energy Network
  Devices
description:
  - Get all Energy Network Devices. - > Retrieves a
    list of network devices with energy data based on
    the specified query parameters. For detailed information
    about the usage of the API, please refer to the
    Open API specification document - https //github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    deviceEnergy_1.0-1.0.1-resolved.yaml.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
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
  limit:
    description:
      - Limit query parameter. Maximum number of records
        to return.
    type: int
  cursor:
    description:
      - >
        Cursor query parameter. It's an opaque string
        field that indicates the next record in the
        requested collection. If no records remain,
        the API returns a response with a count of zero.
        The default value is an empty string, and the
        initial value must be an empty string. The cursor
        value is populated by the API in the response
        page block. If the user wants more records,
        the cursor in the subsequent request must be
        updated with the value from the previous response.
    type: str
  sortBy:
    description:
      - SortBy query parameter. A field within the response
        to sort by.
    type: str
  order:
    description:
      - Order query parameter. The sort order of the
        field ascending or descending.
    type: str
  id:
    description:
      - >
        Id query parameter. The list of Device Uuids
        (e.g., `6bef213c-19ca-4170-8375-b694e251101c`).
        Examples `id=6bef213c-19ca-4170-8375-b694e251101c`
        (single device requested) `id=6bef213c-19ca-4170-8375-b694e251101c&id=32219612-819e-4b5e-a96b-cf22aca13dd9`.
    type: str
  siteId:
    description:
      - >
        SiteId query parameter. The UUID of the site.
        (Ex. `flooruuid`) Examples `?siteId=id1` (single
        id requested) `?siteId=id1&siteId=id2&siteId=id3`
        (multiple ids requested).
    type: str
  siteHierarchy:
    description:
      - >
        SiteHierarchy query parameter. The full hierarchical
        breakdown of the site tree starting from Global
        site name and ending with the specific site
        name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)
        This field supports wildcard asterisk (`*`)
        character search support. E.g. `*/San*, */San,
        /San*` Examples `?siteHierarchy=Global/AreaName/BuildingName/FloorName`
        (single siteHierarchy requested) `?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Gl
        obal/AreaName2/BuildingName2/FloorName2` (multiple
        siteHierarchies requested).
    type: str
  siteHierarchyId:
    description:
      - >
        SiteHierarchyId query parameter. The full hierarchy
        breakdown of the site tree in id form starting
        from Global site UUID and ending with the specific
        site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)
        This field supports wildcard asterisk (`*`)
        character search support. E.g. `*uuid*, *uuid,
        uuid*` Examples `?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid
        `(single siteHierarchyId requested) `?siteH
        ierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2
        /floorUuid2` (multiple siteHierarchyIds requested).
    type: str
  deviceCategory:
    description:
      - >
        DeviceCategory query parameter. The list of
        device deviceCategories. Examples `deviceCategory=Switch`
        (single device family requested) `deviceCategory=Switch&deviceCategory=Router`
        (multiple device categories with comma separator).
    type: str
  deviceSubCategory:
    description:
      - >
        DeviceSubCategory query parameter. The list
        of device sub categories. Examples `deviceSubCategory=Cisco
        Catalyst 9300 Series Switches` (single device
        family requested) `deviceSubCategory=Cisco Catalyst
        9300 Series Switches&deviceSubCategory=Cisco
        Catalyst 9400 Series Switches`.
    type: str
  view:
    description:
      - >
        View query parameter. List of views. View and
        attribute work in union. Each view will include
        its attributes. For example, view device includes
        all the attributes related to device. Please
        refer to `NetworkDeviceEnergyView` model for
        supported list of views Examples `view=device&view=energy`.
    type: str
  attribute:
    description:
      - >
        Attribute query parameter. List of attributes.
        Please refer to `NetworkDeviceEnergyAttribute`
        for supported list of attributes Examples `attribute=id&attribute=energyConsumed`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetDevicesEnergy
    description: Complete reference of the GetDevicesEnergy
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-devices-energy
notes:
  - SDK Method used are
    devices.Devices.get_devices_energy,
  - Paths used are
    get /dna/data/api/v1/energy/networkDevices,
"""

EXAMPLES = r"""
---
- name: Get all Energy Network Devices
  cisco.dnac.energy_network_devices_info:
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
    limit: 0
    cursor: string
    sortBy: string
    order: string
    id: string
    siteId: string
    siteHierarchy: string
    siteHierarchyId: string
    deviceCategory: string
    deviceSubCategory: string
    view: string
    attribute: string
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
          "deviceName": "string",
          "deviceCategory": "string",
          "deviceSubCategory": "string",
          "siteId": "string",
          "siteHierarchy": "string",
          "siteHierarchyId": "string",
          "energyConsumed": 0,
          "estimatedCost": 0,
          "estimatedEmission": 0,
          "carbonIntensity": 0
        }
      ],
      "page": {
        "limit": 0,
        "cursor": "string",
        "count": 0,
        "sortBy": [
          {
            "name": "string",
            "order": "string"
          }
        ]
      },
      "version": "string"
    }
"""
