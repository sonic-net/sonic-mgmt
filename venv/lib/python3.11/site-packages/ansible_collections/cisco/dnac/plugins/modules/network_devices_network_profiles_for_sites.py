#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_network_profiles_for_sites
short_description: Resource module for Network Devices
  Network Profiles For Sites
description:
  - Manage operation delete of the resource Network
    Devices Network Profiles For Sites.
  - Deletes a network profile for sites.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. The `id` of the
      network profile, retrievable from `GET /intent/api/v1/networkProfilesForSites`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      DeletesANetworkProfileForSites
    description: Complete reference of the DeletesANetworkProfileForSites
      API.
    link: https://developer.cisco.com/docs/dna-center/#!deletes-a-network-profile-for-sites
notes:
  - SDK Method used are
    site_design.SiteDesign.deletes_a_network_profile_for_sites,
  - Paths used are
    delete /dna/intent/api/v1/networkProfilesForSites/{id},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.network_devices_network_profiles_for_sites:
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
