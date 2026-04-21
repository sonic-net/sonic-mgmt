#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabric_site
short_description: Resource module for Sda Fabric Site
description:
  - Manage operations create and delete of the resource
    Sda Fabric Site.
  - Add Site in SDA Fabric.
  - Delete Site from SDA Fabric.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  fabricName:
    description: Warning - Starting DNA Center 2.2.3.5
      release, this field has been deprecated. SD-Access
      Fabric does not need it anymore. It will be removed
      in future DNA Center releases.
    type: str
    version_added: 4.0.0
  fabricType:
    description: Type of SD-Access Fabric. Allowed values
      are "FABRIC_SITE" or "FABRIC_ZONE". Default value
      is "FABRIC_SITE".
    type: str
  siteNameHierarchy:
    description: SiteNameHierarchy query parameter.
      Site Name Hierarchy.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddSiteInSDAFabric
    description: Complete reference of the AddSiteInSDAFabric
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-site-in-sda-fabric
  - name: Cisco DNA Center documentation for SDA DeleteSiteFromSDAFabric
    description: Complete reference of the DeleteSiteFromSDAFabric
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-site-from-sda-fabric
notes:
  - SDK Method used are
    sda.Sda.add_site,
    sda.Sda.delete_site,
  - Paths used are
    post /dna/intent/api/v1/business/sda/fabric-site,
    delete /dna/intent/api/v1/business/sda/fabric-site,
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.sda_fabric_site:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    siteNameHierarchy: string
- name: Create
  cisco.dnac.sda_fabric_site:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    fabricName: string
    fabricType: string
    siteNameHierarchy: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "status": "string",
      "description": "string",
      "taskId": "string",
      "taskStatusUrl": "string",
      "executionStatusUrl": "string",
      "executionId": "string"
    }
"""
