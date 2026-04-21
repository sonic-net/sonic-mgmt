#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: planned_access_points
short_description: Resource module for Planned Access
  Points
description:
  - Manage operations create, update and delete of the
    resource Planned Access Points. - > Allows creation
    of a new planned access point on an existing floor
    map including its planned radio and antenna details.
    Use the Get variant of this API to fetch any existing
    planned access points for the floor. The payload
    to create a planned access point is in the same
    format, albeit a single object instead of a list,
    of that API. - > Allow to delete a planned access
    point from an existing floor map including its planned
    radio and antenna details. Use the Get variant of
    this API to fetch the existing planned access points
    for the floor. The instanceUUID listed in each of
    the planned access point attributes acts as the
    path param input to this API to delete that specific
    instance. - > Allows updating a planned access point
    on an existing floor map including its planned radio
    and antenna details. Use the Get variant of this
    API to fetch the existing planned access points
    for the floor. The payload to update a planned access
    point is in the same format, albeit a single object
    instead of a list, of that API.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  attributes:
    description: Planned Access Points's attributes.
    suboptions:
      createDate:
        description: Created date of the planned access
          point.
        type: float
      domain:
        description: Service domain to which the planned
          access point belongs.
        type: str
      heirarchyName:
        description: Hierarchy name of the planned access
          point.
        type: str
      id:
        description: Unique id of the planned access
          point.
        type: float
      instanceUuid:
        description: Instance uuid of the planned access
          point.
        type: str
      macAddress:
        description: MAC address of the planned access
          point.
        type: str
      name:
        description: Display name of the planned access
          point.
        type: str
      source:
        description: Source of the data used to create
          the planned access point.
        type: str
      typeString:
        description: Type string representation of the
          planned access point.
        type: str
    type: dict
  floorId:
    description: FloorId path parameter. The instance
      UUID of the floor hierarchy element.
    type: str
  isSensor:
    description: Indicates that PAP is a sensor.
    type: bool
  location:
    description: Planned Access Points's location.
    suboptions:
      altitude:
        description: Altitude of the planned access
          point's location.
        type: float
      lattitude:
        description: Latitude of the planned access
          point's location.
        type: float
      longtitude:
        description: Longitude of the planned access
          point's location.
        type: float
    type: dict
  plannedAccessPointUuid:
    description: PlannedAccessPointUuid path parameter.
      The instance UUID of the planned access point
      to delete.
    type: str
  position:
    description: Planned Access Points's position.
    suboptions:
      x:
        description: X-coordinate of the planned access
          point on the map, 0,0 point being the top-left
          corner.
        type: float
      y:
        description: Y-coordinate of the planned access
          point on the map, 0,0 point being the top-left
          corner.
        type: float
      z:
        description: Z-coordinate, or height, of the
          planned access point on the map.
        type: float
    type: dict
  radioCount:
    description: Number of radios of the planned access
      point.
    type: int
  radios:
    description: Planned Access Points's radios.
    elements: dict
    suboptions:
      antenna:
        description: Planned Access Points's antenna.
        suboptions:
          azimuthAngle:
            description: Azimuth angle of the antenna.
            type: float
          elevationAngle:
            description: Elevation angle of the antenna.
            type: float
          gain:
            description: Gain of the antenna.
            type: float
          mode:
            description: Mode of the antenna associated
              with this radio.
            type: str
          name:
            description: Name of the antenna.
            type: str
          type:
            description: Type of the antenna associated
              with this radio.
            type: str
        type: dict
      attributes:
        description: Planned Access Points's attributes.
        suboptions:
          channel:
            description: Channel in which this radio
              operates.
            type: float
          channelString:
            description: Channel string representation.
            type: str
          id:
            description: Id of the radio.
            type: int
          ifMode:
            description: IF mode of the radio.
            type: str
          ifTypeString:
            description: String representation of native
              band.
            type: str
          ifTypeSubband:
            description: Sub band of the radio.
            type: str
          instanceUuid:
            description: Instance Uuid of the radio.
            type: str
          slotId:
            description: Slot number in which the radio
              resides in the parent access point.
            type: float
          txPowerLevel:
            description: Tx Power at which this radio
              operates (in dBm).
            type: float
        type: dict
      isSensor:
        description: Determines if it is sensor or not.
        type: bool
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      CreatePlannedAccessPointForFloor
    description: Complete reference of the CreatePlannedAccessPointForFloor
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-planned-access-point-for-floor
  - name: Cisco DNA Center documentation for Devices
      DeletePlannedAccessPointForFloor
    description: Complete reference of the DeletePlannedAccessPointForFloor
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-planned-access-point-for-floor
  - name: Cisco DNA Center documentation for Devices
      UpdatePlannedAccessPointForFloor
    description: Complete reference of the UpdatePlannedAccessPointForFloor
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-planned-access-point-for-floor
notes:
  - SDK Method used are
    devices.Devices.create_planned_access_point_for_floor,
    devices.Devices.delete_planned_access_point_for_floor,
    devices.Devices.update_planned_access_point_for_floor,
  - Paths used are
    post /dna/intent/api/v1/floors/{floorId}/planned-access-points,
    delete /dna/intent/api/v1/floors/{floorId}/planned-access-points/{plannedAccessPointUuid},
    put /dna/intent/api/v1/floors/{floorId}/planned-access-points,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.planned_access_points:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    attributes:
      createDate: 0
      domain: string
      heirarchyName: string
      id: 0
      instanceUuid: string
      macAddress: string
      name: string
      source: string
      typeString: string
    floorId: string
    isSensor: true
    location:
      altitude: 0
      lattitude: 0
      longtitude: 0
    position:
      x: 0
      y: 0
      z: 0
    radioCount: 0
    radios:
      - antenna:
          azimuthAngle: 0
          elevationAngle: 0
          gain: 0
          mode: string
          name: string
          type: string
        attributes:
          channel: 0
          channelString: string
          id: 0
          ifMode: string
          ifTypeString: string
          ifTypeSubband: string
          instanceUuid: string
          slotId: 0
          txPowerLevel: 0
        isSensor: true
- name: Create
  cisco.dnac.planned_access_points:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    attributes:
      createDate: 0
      domain: string
      heirarchyName: string
      id: 0
      instanceUuid: string
      macAddress: string
      name: string
      source: string
      typeString: string
    floorId: string
    isSensor: true
    location:
      altitude: 0
      lattitude: 0
      longtitude: 0
    position:
      x: 0
      y: 0
      z: 0
    radioCount: 0
    radios:
      - antenna:
          azimuthAngle: 0
          elevationAngle: 0
          gain: 0
          mode: string
          name: string
          type: string
        attributes:
          channel: 0
          channelString: string
          id: 0
          ifMode: string
          ifTypeString: string
          ifTypeSubband: string
          instanceUuid: string
          slotId: 0
          txPowerLevel: 0
        isSensor: true
- name: Delete by id
  cisco.dnac.planned_access_points:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    floorId: string
    plannedAccessPointUuid: string
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
