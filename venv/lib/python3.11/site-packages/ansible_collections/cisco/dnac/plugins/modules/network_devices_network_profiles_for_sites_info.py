#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_network_profiles_for_sites_info
short_description: Information module for Network Devices
  Network Profiles For Sites
description:
  - Get all Network Devices Network Profiles For Sites.
  - Get Network Devices Network Profiles For Sites by
    id.
  - Retrieves a network profile for sites by id.
  - Retrieves the list of network profiles for sites.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
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
  sortBy:
    description:
      - SortBy query parameter. A property within the
        response to sort by.
    type: str
  order:
    description:
      - Order query parameter. Whether ascending or
        descending order should be used to sort the
        response.
    type: str
  type:
    description:
      - Type query parameter. Filter responses to only
        include profiles of a given type.
    type: str
  id:
    description:
      - Id path parameter. The `id` of the network profile,
        retrievable from `GET /intent/api/v1/networkProfilesForSites`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      RetrieveANetworkProfileForSitesById
    description: Complete reference of the RetrieveANetworkProfileForSitesById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-a-network-profile-for-sites-by-id
  - name: Cisco DNA Center documentation for Site Design
      RetrievesTheListOfNetworkProfilesForSites
    description: Complete reference of the RetrievesTheListOfNetworkProfilesForSites
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-list-of-network-profiles-for-sites
notes:
  - SDK Method used are
    site_design.SiteDesign.retrieve_a_network_profile_for_sites_by_id,
    site_design.SiteDesign.retrieves_the_list_of_network_profiles_for_sites,
  - Paths used are
    get /dna/intent/api/v1/networkProfilesForSites,
    get /dna/intent/api/v1/networkProfilesForSites/{id},
"""

EXAMPLES = r"""
---
- name: Get all Network Devices Network Profiles For
    Sites
  cisco.dnac.network_devices_network_profiles_for_sites_info:
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
    sortBy: string
    order: string
    type: string
  register: result
- name: Get Network Devices Network Profiles For Sites
    by id
  cisco.dnac.network_devices_network_profiles_for_sites_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
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
        "name": "string",
        "type": "string"
      }
    }
"""
