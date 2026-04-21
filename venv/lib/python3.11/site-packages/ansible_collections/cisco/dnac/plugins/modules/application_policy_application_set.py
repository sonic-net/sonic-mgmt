#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: application_policy_application_set
short_description: Resource module for Application Policy
  Application Set
description:
  - Manage operations create and delete of the resource
    Application Policy Application Set.
  - Create new custom application set/s.
  - Delete existing custom application set by id.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Id of custom application
      set to delete.
    type: str
  payload:
    description: Application Policy Application Set's
      payload.
    elements: dict
    suboptions:
      defaultBusinessRelevance:
        description: Default business relevance.
        type: str
      name:
        description: Application Set name.
        type: str
      namespace:
        description: Namespace, should be set to scalablegroup
          application.
        type: str
      qualifier:
        description: Qualifier, should be set to application.
        type: str
      scalableGroupExternalHandle:
        description: Scalable group external handle,
          should be set to application set name.
        type: str
      scalableGroupType:
        description: Scalable group type, should be
          set to APPLICATION_GROUP.
        type: str
      type:
        description: Type, should be set to scalablegroup.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy CreateApplicationSetsV2
    description: Complete reference of the CreateApplicationSetsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-application-sets-v-2
  - name: Cisco DNA Center documentation for Application
      Policy DeleteApplicationSetV2
    description: Complete reference of the DeleteApplicationSetV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-application-set-v-2
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.create_application_sets_v2,
    application_policy.ApplicationPolicy.delete_application_set_v2,
  - Paths used are
    post /dna/intent/api/v2/application-policy-application-set,
    delete /dna/intent/api/v2/application-policy-application-set/{id},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.application_policy_application_set:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - defaultBusinessRelevance: string
        name: string
        namespace: string
        qualifier: string
        scalableGroupExternalHandle: string
        scalableGroupType: string
        type: string
- name: Delete by id
  cisco.dnac.application_policy_application_set:
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
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
