#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sites_ntp_settings
short_description: Resource module for Sites Ntp Settings
description:
  - Manage operation update of the resource Sites Ntp
    Settings. - > Set NTP settings for a site; `null`
    values indicate that the setting will be inherited
    from the parent site; empty objects `{}` indicate
    that the settings is unset.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Site Id.
    type: str
  ntp:
    description: Sites Ntp Settings's ntp.
    suboptions:
      servers:
        description: NTP servers to facilitate system
          clock synchronization for your network. Max
          10.
        elements: str
        type: list
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings SetNTPSettingsForASite
    description: Complete reference of the SetNTPSettingsForASite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!set-ntp-settings-for-a-site
notes:
  - SDK Method used are
    network_settings.NetworkSettings.set_n_t_p_settings_for_a_site,
  - Paths used are
    put /dna/intent/api/v1/sites/{id}/ntpSettings,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.sites_ntp_settings:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    id: string
    ntp:
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
