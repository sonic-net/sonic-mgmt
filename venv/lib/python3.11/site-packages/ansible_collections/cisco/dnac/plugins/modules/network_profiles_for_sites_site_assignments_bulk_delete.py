#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_profiles_for_sites_site_assignments_bulk_delete
short_description: Resource module for Network Profiles
  For Sites Site Assignments Bulk Delete
description:
  - Manage operation delete of the resource Network
    Profiles For Sites Site Assignments Bulk Delete.
    - > Unassigns a given network profile for sites
    from multiple sites. The profile must be removed
    from the containing building first if this site
    is a floor.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  profileId:
    description: ProfileId path parameter. The `id`
      of the network profile, retrievable from `GET
      /intent/api/v1/networkProfilesForSites`.
    type: str
  siteId:
    description: SiteId query parameter. The id or ids
      of the network profile, retrievable from /dna/intent/api/v1/sites..
      A list of profile ids can be passed as a queryParameter
      in two ways 1. A comma-separated string ( siteId=388a23e9-4739-4be7-a0aa-cc5a95d158dd,2726dc60-3a12-451e-947a...
      or... 2. As separate query parameters with the
      same name ( siteId=388a23e9-4739-4be7-a0aa-cc5a95d158dd&siteId...
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      UnassignsANetworkProfileForSitesFromMultipleSites
    description: Complete reference of the UnassignsANetworkProfileForSitesFromMultipleSites
      API.
    link: https://developer.cisco.com/docs/dna-center/#!unassigns-a-network-profile-for-sites-from-multiple-sites
notes:
  - SDK Method used are
    site_design.SiteDesign.unassigns_a_network_profile_for_sites_from_multiple_sites,
  - Paths used are
    delete /dna/intent/api/v1/networkProfilesForSites/{profileId}/siteAssignments/bulk,
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.network_profiles_for_sites_site_assignments_bulk_delete:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    profileId: string
    siteId: string
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
