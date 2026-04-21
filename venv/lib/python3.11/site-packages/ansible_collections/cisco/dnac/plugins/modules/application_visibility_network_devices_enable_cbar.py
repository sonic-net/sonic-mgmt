#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: application_visibility_network_devices_enable_cbar
short_description: Resource module for Application Visibility
  Network Devices Enable Cbar
description:
  - Manage operation create of the resource Application
    Visibility Network Devices Enable Cbar. - > This
    API can be used to enable CBAR feature on multiple
    network devices. Request payload should include
    the list of network devices where CBAR has to be
    enabled. It can optionally include list of interfaces
    wired or WLAN modes wireless to be excluded from
    CBAR enablement.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  networkDevices:
    description: Application Visibility Network Devices
      Enable Cbar's networkDevices.
    elements: dict
    suboptions:
      excludeInterfaceIds:
        description: List of interface identifiers which
          needs to be excluded from CBAR enablement.
          Applicable only for wired devices. Please
          note that this list considered as absolute
          exclusion and earlier exclusions are not considered.
          For example, if IF1 and IF2 have already been
          excluded from CBAR as part of earlier enablement,
          and this API is now called with IF3 and IF4
          as inputs, then IF1 and IF2 are removed from
          exclusion list and only IF3 and IF4 are excluded.
        elements: str
        type: list
      excludeWlanModes:
        description: WLAN modes which needs to be excluded
          from CBAR enablement. Applicable only for
          wireless devices. Applicable values are LOCAL,
          FLEX, or FABRIC.
        elements: str
        type: list
      id:
        description: Network device identifier.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy EnableCBARFeatureOnMultipleNetworkDevices
    description: Complete reference of the EnableCBARFeatureOnMultipleNetworkDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!enable-cbar-feature-on-multiple-network-devices
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.enable_c_b_a_r_feature_on_multiple_network_devices,
  - Paths used are
    post /dna/intent/api/v1/applicationVisibility/networkDevices/enableCbar,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.application_visibility_network_devices_enable_cbar:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    networkDevices:
      - excludeInterfaceIds:
          - string
        excludeWlanModes:
          - string
        id: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
