#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: templates_template_id_network_profiles_for_sites_bulk_delete
short_description: Resource module for Templates Template
  Id Network Profiles For Sites Bulk Delete
description:
  - Manage operation delete of the resource Templates
    Template Id Network Profiles For Sites Bulk Delete.
  - Detach a list of network profiles from a Day-N CLI
    template with a list of profile IDs along with the
    template ID.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  profileId:
    description: ProfileId query parameter. The id or
      ids of the network profile, retrievable from /dna/intent/api/v1/networkProfilesForSites.
      The maximum number of profile Ids allowed is 20.
      A list of profile ids can be passed as a queryParameter
      in two ways a comma-separated string ( profileId=388a23e9-4739-4be7-a0aa-cc5a95d158dd,2726dc60-3a12-451e-947a-d9...
      or... As separate query parameters with the same
      name ( profileId=388a23e9-4739-4be7-a0aa-cc5a95d158dd&profil...
    type: str
  templateId:
    description: TemplateId path parameter. The `id`
      of the template, retrievable from `GET /intent/api/v1/templates`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates DetachAListOfNetworkProfilesFromADayNCLITemplate
    description: Complete reference of the DetachAListOfNetworkProfilesFromADayNCLITemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!detach-a-list-of-network-profiles-from-a-day-ncli-template
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.detach_a_list_of_network_profiles_from_a_day_n_cli_template,
  - Paths used are
    delete /dna/intent/api/v1/templates/{templateId}/networkProfilesForSites/bulk,
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.templates_template_id_network_profiles_for_sites_bulk_delete:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    profileId: string
    templateId: string
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
