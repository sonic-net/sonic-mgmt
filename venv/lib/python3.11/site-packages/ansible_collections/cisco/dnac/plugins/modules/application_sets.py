#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: application_sets
short_description: Resource module for Application Sets
description:
  - Manage operations create and delete of the resource
    Application Sets.
  - Create new custom application-set/s.
  - Delete existing application-set by it's id.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id query parameter.
    type: str
  payload:
    description: Application Sets's payload.
    elements: dict
    suboptions:
      name:
        description: Name.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy CreateApplicationSet
    description: Complete reference of the CreateApplicationSet
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-application-set
  - name: Cisco DNA Center documentation for Application
      Policy DeleteApplicationSet
    description: Complete reference of the DeleteApplicationSet
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-application-set
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.create_application_set,
    application_policy.ApplicationPolicy.delete_application_set,
  - Paths used are
    post /dna/intent/api/v1/application-policy-application-set,
    delete /dna/intent/api/v1/application-policy-application-set,
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.application_sets:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
- name: Create
  cisco.dnac.application_sets:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - name: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "taskId": "string",
      "url": "string"
    }
"""
