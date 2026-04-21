#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sites_image_distribution_settings
short_description: Resource module for Sites Image Distribution
  Settings
description:
  - Manage operation update of the resource Sites Image
    Distribution Settings. - > Set image distribution
    settings for a site; `null` values indicate that
    the setting will be inherited from the parent site;
    empty objects `{}` indicate that the settings is
    unset.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Site Id.
    type: str
  imageDistribution:
    description: Sites Image Distribution Settings's
      imageDistribution.
    suboptions:
      servers:
        description: "This field holds an array of unique
          identifiers representing image distribution
          servers. Use '/intent/api/v1/images/distributionServerSettings'
          to find the Image distribution server Id.
          Max 2. Use SFTP servers to act as image distribution
          servers. A distributed SWIM architecture,
          using suitably located SFTP servers, can help
          support large-scale device software image
          upgrades and conserve WAN bandwidth."
        elements: str
        type: list
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings SetImageDistributionSettingsForASite
    description: Complete reference of the SetImageDistributionSettingsForASite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!set-image-distribution-settings-for-a-site
notes:
  - SDK Method used are
    network_settings.NetworkSettings.set_image_distribution_settings_for_a_site,
  - Paths used are
    put /dna/intent/api/v1/sites/{id}/imageDistributionSettings,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.sites_image_distribution_settings:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    id: string
    imageDistribution:
      servers:
        - string
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
