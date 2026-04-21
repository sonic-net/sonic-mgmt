#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: templates_template_id_network_profiles_for_sites_profile_id_delete
short_description: Resource module for Templates Template
  Id Network Profiles For Sites Profile Id Delete
description:
  - Manage operation delete of the resource Templates
    Template Id Network Profiles For Sites Profile Id
    Delete.
  - Detach a network profile from a Day-N CLI template
    by the profile ID and template ID.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  profileId:
    description: ProfileId path parameter. The `id`
      of the network profile, retrievable from `GET
      /intent/api/v1/networkProfilesForSites`.
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
      Templates DetachANetworkProfileFromADayNCLITemplate
    description: Complete reference of the DetachANetworkProfileFromADayNCLITemplate
      API.
    link: https://developer.cisco.com/docs/dna-center/#!detach-a-network-profile-from-a-day-ncli-template
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.detach_a_network_profile_from_a_day_n_cli_template,
  - Paths used are
    delete /dna/intent/api/v1/templates/{templateId}/networkProfilesForSites/{profileId},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.templates_template_id_network_profiles_for_sites_profile_id_delete:
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
