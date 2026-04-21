#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_profiles_for_sites_site_assignments
short_description: Resource module for Network Profiles
  For Sites Site Assignments
description:
  - Manage operations create and delete of the resource
    Network Profiles For Sites Site Assignments.
  - Assigns a given network profile for sites to a given
    site. Also assigns the profile to child sites. -
    > Unassigns a given network profile for sites from
    a site. The profile must be removed from parent
    sites first, otherwise this operation will not ulimately
    unassign the profile.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id.
    type: str
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
      AssignANetworkProfileForSitesToTheGivenSite
    description: Complete reference of the AssignANetworkProfileForSitesToTheGivenSite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!assign-a-network-profile-for-sites-to-the-given-site
  - name: Cisco DNA Center documentation for Site Design
      UnassignsANetworkProfileForSitesFromASite
    description: Complete reference of the UnassignsANetworkProfileForSitesFromASite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!unassigns-a-network-profile-for-sites-from-a-site
notes:
  - SDK Method used are
    site_design.SiteDesign.assign_a_network_profile_for_sites_to_the_given_site,
    site_design.SiteDesign.unassigns_a_network_profile_for_sites_from_a_site,
  - Paths used are
    post /dna/intent/api/v1/networkProfilesForSites/{profileId}/siteAssignments,
    delete /dna/intent/api/v1/networkProfilesForSites/{profileId}/siteAssignments/{id},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_profiles_for_sites_site_assignments:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    id: string
    profileId: string
- name: Delete by id
  cisco.dnac.network_profiles_for_sites_site_assignments:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
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
