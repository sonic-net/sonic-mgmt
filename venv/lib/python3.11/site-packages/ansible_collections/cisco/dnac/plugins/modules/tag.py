#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tag
short_description: Resource module for Tag
description:
  - Manage operations create, update and delete of the
    resource Tag.
  - Creates tag with specified tag attributes.
  - Deletes a tag specified by id.
  - Updates a tag specified by id.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  description:
    description: Description of the tag.
    type: str
  dynamicRules:
    description: Tag's dynamicRules.
    elements: dict
    suboptions:
      memberType:
        description: MemberType of the tag (e.g. Networkdevice,
          interface).
        type: str
      rules:
        description: Tag's rules.
        suboptions:
          items:
            description: Items details,multiple rules
              can be defined by items(e.g. "items" {"operation"
              "ILIKE", "name" "managementIpAddress",
              "value" "%10%"}, {"operation" "ILIKE",
              "name" "hostname", "value" "%NA%"} ).
            elements: dict
            type: list
          name:
            description: Name of the parameter (e.g.
              For interface portName,adminStatus,speed,status,description.
              For networkdevice family,series,hostname,managementIpAddress,groupNameHierarchy,softwareVersion).
            type: str
          operation:
            description: Opeartion used in the rules
              (e.g. OR,IN,EQ,LIKE,ILIKE,AND).
            type: str
          value:
            description: Value of the parameter (e.g.
              For portName 1/0/1,for adminStatus,status
              up/down, for speed any integer value,
              for description any valid string, for
              family switches, for series C3650, for
              managementIpAddress 10.197.124.90, groupNameHierarchy
              Global, softwareVersion 16.9.1).
            type: str
          values:
            description: Values of the parameter,Only
              one of the value or values can be used
              for the given parameter. (for managementIpAddress
              e.g. "10.197.124.90","10.197.124.91").
            elements: str
            type: list
        type: dict
    type: list
  id:
    description: Mandatory instanceUuid of the tag that
      needs to be updated.
    type: str
  instanceTenantId:
    description: InstanceTenantId generated for the
      tag.
    type: str
  name:
    description: Name of the tag.
    type: str
  systemTag:
    description: True for system created tags, false
      for user defined tags.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Tag CreateTag
    description: Complete reference of the CreateTag
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-tag
  - name: Cisco DNA Center documentation for Tag DeleteTag
    description: Complete reference of the DeleteTag
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-tag
  - name: Cisco DNA Center documentation for Tag UpdateTag
    description: Complete reference of the UpdateTag
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-tag
notes:
  - SDK Method used are
    tag.Tag.create_tag,
    tag.Tag.delete_tag,
    tag.Tag.update_tag,
  - Paths used are
    post /dna/intent/api/v1/tag,
    delete
    /dna/intent/api/v1/tag/{id},
    put /dna/intent/api/v1/tag,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.tag:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    description: string
    dynamicRules:
      - memberType: string
        rules:
          items:
            - {}
          name: string
          operation: string
          value: string
          values:
            - string
    id: string
    instanceTenantId: string
    name: string
    systemTag: true
- name: Create
  cisco.dnac.tag:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    description: string
    dynamicRules:
      - memberType: string
        rules:
          items:
            - {}
          name: string
          operation: string
          value: string
          values:
            - string
    id: string
    instanceTenantId: string
    name: string
    systemTag: true
- name: Delete by id
  cisco.dnac.tag:
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
        "taskId": "string",
        "url": "string"
      }
    }
"""
