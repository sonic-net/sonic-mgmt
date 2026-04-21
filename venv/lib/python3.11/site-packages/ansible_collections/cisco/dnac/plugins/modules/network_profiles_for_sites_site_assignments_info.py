#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_profiles_for_sites_site_assignments_info
short_description: Information module for Network Profiles
  For Sites Site Assignments
description:
  - Get all Network Profiles For Sites Site Assignments.
  - Retrieves the list of sites that the given network
    profile for sites is assigned to.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  profileId:
    description:
      - >
        ProfileId path parameter. The `id` of the network
        profile, retrievable from `GET /intent/api/v1/networkProfilesForSites`.
    type: str
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: float
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page;The minimum is 1, and
        the maximum is 500.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      RetrievesTheListOfSitesThatTheGivenNetworkProfileForSitesIsAssignedTo
    description: Complete reference of the RetrievesTheListOfSitesThatTheGivenNetworkProfileForSitesIsAssignedTo
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-list-of-sites-that-the-given-network-profile-for-sites-is-assigned-to
notes:
  - SDK Method used are
    site_design.SiteDesign.retrieves_the_list_of_sites_that_the_given_network_profile_for_sites_is_assigned_to,
  - Paths used are
    get /dna/intent/api/v1/networkProfilesForSites/{profileId}/siteAssignments,
"""

EXAMPLES = r"""
---
- name: Get all Network Profiles For Sites Site Assignments
  cisco.dnac.network_profiles_for_sites_site_assignments_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    offset: 0
    limit: 0
    profileId: string
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
          "id": "string"
        }
      ],
      "version": "string"
    }
"""
