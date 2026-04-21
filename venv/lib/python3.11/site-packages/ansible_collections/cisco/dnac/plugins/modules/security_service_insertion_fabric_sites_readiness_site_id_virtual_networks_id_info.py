#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_service_insertion_fabric_sites_readiness_site_id_virtual_networks_id_info
short_description: Information module for Security Service
  Insertion Fabric Sites Readiness Site Id Virtual Networks
  Id
description:
  - Get Security Service Insertion Fabric Sites Readiness
    Site Id Virtual Networks Id by id. - > Retrieves
    a list of switches list of switches for the specified
    virtual network within a fabric site, including
    their individual readiness status for Security Service
    Insertion SSI deployment.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description:
      - SiteId path parameter. Sda fabric site id.
    type: str
  id:
    description:
      - Id path parameter. Virtual network id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA ReadinessStatusOfSwitchesInASpecifiedVirtualNetworkWithinAFabricSite
    description: Complete reference of the ReadinessStatusOfSwitchesInASpecifiedVirtualNetworkWithinAFabricSite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!readiness-status-of-switches-in-a-specified-virtual-network-within-a-fabric-site
notes:
  - SDK Method used are
    sda.Sda.readiness_status_of_switches_in_a_specified_virtual_network_within_a_fabric_site,
  - Paths used are
    get /dna/intent/api/v1/securityServiceInsertion/fabricSitesReadiness/{siteId}/virtualNetworks/{id},
"""

EXAMPLES = r"""
---
- name: Get Security Service Insertion Fabric Sites
    Readiness Site Id Virtual Networks Id by id
  cisco.dnac.security_service_insertion_fabric_sites_readiness_site_id_virtual_networks_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
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
      "response": [
        {
          "id": "string",
          "hostName": "string",
          "ipAddress": "string",
          "reachabilityStatus": "string",
          "version": "string",
          "license": "string",
          "readiness": "string",
          "fabricRoles": [
            "string"
          ]
        }
      ],
      "version": "string"
    }
"""
