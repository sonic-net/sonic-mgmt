#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_profiles_for_sites_site_assignments_bulk_create
short_description: Resource module for Network Profiles
  For Sites Site Assignments Bulk Create
description:
  - Manage operation create of the resource Network
    Profiles For Sites Site Assignments Bulk Create.
  - Assign a network profile for sites to a list of
    sites. Also assigns the profile to child sites.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  items:
    description: Items.
    elements: dict
    suboptions:
      id:
        description: Id.
        type: str
    type: list
  profileId:
    description: ProfileId path parameter. The `id`
      of the network profile, retrievable from `GET
      /intent/api/v1/networkProfilesForSites`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      AssignANetworkProfileForSitesToAListOfSites
    description: Complete reference of the AssignANetworkProfileForSitesToAListOfSites
      API.
    link: https://developer.cisco.com/docs/dna-center/#!assign-a-network-profile-for-sites-to-a-list-of-sites
notes:
  - SDK Method used are
    site_design.SiteDesign.assign_a_network_profile_for_sites_to_a_list_of_sites,
  - Paths used are
    post /dna/intent/api/v1/networkProfilesForSites/{profileId}/siteAssignments/bulk,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_profiles_for_sites_site_assignments_bulk_create:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    items:
      - - id: string
    profileId: string
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
