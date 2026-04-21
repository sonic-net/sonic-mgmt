#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: buildings
short_description: Resource module for Buildings
description:
  - Manage operations create, update and delete of the
    resource Buildings.
  - Creates a building in the network hierarchy under
    area. - > Deletes building in the network hierarchy.
    This operations fails if there are any floors for
    this building, or if there are any devices assigned
    to this building.
  - Updates a building in the network hierarchy.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  address:
    description: Building address. Example 4900 Marie
      P. Debartolo Way, Santa Clara, California 95054,
      United States. Please note that if only the address
      is provided when creating a building, the UI will
      not display the geo-location on the map. To ensure
      the location is rendered, you must also provide
      the latitude and longitude. If a building has
      been created without these coordinates and you
      wish to display its geo-location on the map later,
      you can edit the building details via the UI to
      include the latitude and longitude. This limitation
      will be resolved in a future release.
    type: str
  country:
    description: Country name.
    type: str
  id:
    description: Id path parameter. Building Id.
    type: str
  latitude:
    description: Building Latitude. Example 37.403712.
    type: float
  longitude:
    description: Building Longitude. Example -121.971063.
    type: float
  name:
    description: Building name.
    type: str
  parentId:
    description: Parent Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      CreatesABuildingV2
    description: Complete reference of the CreatesABuildingV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!creates-a-building-v-2
  - name: Cisco DNA Center documentation for Site Design
      DeletesABuildingV2
    description: Complete reference of the DeletesABuildingV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!deletes-a-building-v-2
  - name: Cisco DNA Center documentation for Site Design
      UpdatesABuildingV2
    description: Complete reference of the UpdatesABuildingV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!updates-a-building-v-2
notes:
  - SDK Method used are
    site_design.SiteDesign.creates_a_building_v2,
    site_design.SiteDesign.deletes_a_building_v2,
    site_design.SiteDesign.updates_a_building_v2,
  - Paths used are
    post /dna/intent/api/v2/buildings,
    delete /dna/intent/api/v2/buildings/{id},
    put /dna/intent/api/v2/buildings/{id},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.buildings:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    address: string
    country: string
    latitude: 0
    longitude: 0
    name: string
    parentId: string
- name: Update by id
  cisco.dnac.buildings:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    address: string
    country: string
    id: string
    latitude: 0
    longitude: 0
    name: string
    parentId: string
- name: Delete by id
  cisco.dnac.buildings:
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
      "version": "string",
      "response": {
        "url": "string",
        "taskId": "string"
      }
    }
"""
