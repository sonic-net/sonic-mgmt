#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sites_profile_assignments_count_info
short_description: Information module for Sites Profile
  Assignments Count
description:
  - Get all Sites Profile Assignments Count. - > Retrieves
    the count of profiles that the given site has been
    assigned. These profiles may either be directly
    assigned to this site, or were assigned to a parent
    site and have been inherited.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description:
      - SiteId path parameter. The `id` of the site,
        retrievable from `/dna/intent/api/v1/sites`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      RetrievesTheCountOfProfilesThatTheGivenSiteHasBeenAssigned
    description: Complete reference of the RetrievesTheCountOfProfilesThatTheGivenSiteHasBeenAssigned
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-count-of-profiles-that-the-given-site-has-been-assigned
notes:
  - SDK Method used are
    site_design.SiteDesign.retrieves_the_count_of_profiles_that_the_given_site_has_been_assigned,
  - Paths used are
    get /dna/intent/api/v1/sites/{siteId}/profileAssignments/count,
"""

EXAMPLES = r"""
---
- name: Get all Sites Profile Assignments Count
  cisco.dnac.sites_profile_assignments_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
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
        "count": 0
      },
      "version": "string"
    }
"""
