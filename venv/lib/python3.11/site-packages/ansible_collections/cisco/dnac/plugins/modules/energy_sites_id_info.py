#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: energy_sites_id_info
short_description: Information module for Energy Sites
  Id
description:
  - Get Energy Sites Id by id. - > Retrieve the energy
    summary data for a specific site based on the site
    ID. For detailed information about the usage of
    the API, please refer to the Open API specification
    document - https //github.com/cisco-en- programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-
    sitesEnergy-1.0.1-resolved.yaml.
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
      - Id path parameter. The UUID of the Site. (Ex.
        "6bef213c-19ca-4170-8375-b694e251101c").
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
  views:
    description:
      - >
        Views query parameter. The specific summary
        view being requested. This is an optional parameter
        which can be passed to get one or more of the
        specific health data summaries associated with
        sites. ### Response data proviced by each view
        1. **Site** id, siteHierarchy, siteHierarchyId,
        siteType, latitude, longitude 2. **Energy**
        energyConsumed, estimatedCost, estimatedEmission,
        carbonIntensity, numberOfDevices When this query
        parameter is not added the default summaries
        are **site,energy** Examples views=site (single
        view requested) views=site,energy (multiple
        views requested).
    type: str
  attribute:
    description:
      - >
        Attribute query parameter. Supported Attributes
        id, siteHierarchy, siteHierarchyId, siteType,
        latitude, longitude, energyConsumed, estimatedCost,
        estimatedEmission, carbonIntensity, numberOfDevices
        If length of attribute list is too long, please
        use 'view' param instead. Examples attribute=siteHierarchy
        (single attribute requested) attribute=siteHierarchy&attribute=energyConsumed
        (multiple attributes requested).
    type: str
  deviceCategory:
    description:
      - >
        DeviceCategory query parameter. The list of
        device categories. Note that this filter specifies
        which devices will be included when calculating
        energy consumption values, rather than specifying
        the list of returned sites. Examples `deviceCategory=Switch`
        (single device category requested) `deviceCategory=Switch&deviceCategory=Router`
        (multiple device categories with comma separator).
    type: str
  taskId:
    description:
      - >
        TaskId query parameter. Used to retrieve asynchronously
        processed & stored data. When this parameter
        is used, the rest of the request params will
        be ignored.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sites GetSiteEnergyByID
    description: Complete reference of the GetSiteEnergyByID
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-site-energy-by-id
notes:
  - SDK Method used are
    sites.Sites.get_site_energy_by_id,
  - Paths used are
    get /dna/data/api/v1/energy/sites/{id},
"""

EXAMPLES = r"""
---
- name: Get Energy Sites Id by id
  cisco.dnac.energy_sites_id_info:
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
    views: string
    attribute: string
    deviceCategory: string
    taskId: string
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
        "siteName": "string",
        "siteHierarchy": "string",
        "siteHierarchyId": "string",
        "siteType": "string",
        "latitude": 0,
        "longitude": 0,
        "deviceCategories": [
          "string"
        ],
        "energyConsumed": 0,
        "estimatedCost": 0,
        "estimatedEmission": 0,
        "carbonIntensity": 0,
        "numberOfDevices": 0
      },
      "version": "string"
    }
"""
