#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: templates_template_id_network_profiles_for_sites_count_info
short_description: Information module for Templates
  Template Id Network Profiles For Sites Count
description:
  - Get all Templates Template Id Network Profiles For
    Sites Count.
  - Retrieves the count of network profiles that a CLI
    template has been attached to by the template ID.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  templateId:
    description:
      - TemplateId path parameter. The `id` of the template,
        retrievable from `GET /intent/api/v1/templates`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates RetrieveCountOfNetworkProfilesAttachedToACLITemplate
    description: Complete reference of the RetrieveCountOfNetworkProfilesAttachedToACLITemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-count-of-network-profiles-attached-to-acli-template
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.retrieve_count_of_network_profiles_attached_to_acl_i_template,
  - Paths used are
    get /dna/intent/api/v1/templates/{templateId}/networkProfilesForSites/count,
"""

EXAMPLES = r"""
---
- name: Get all Templates Template Id Network Profiles
    For Sites Count
  cisco.dnac.templates_template_id_network_profiles_for_sites_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    templateId: string
  register: result
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
        "count": 0
      }
    }
"""
