#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_pod_profile
version_added: "2.11.0"
short_description: Manage Pod Profiles on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Pod Profiles on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.2 (NDO v4.4) and later.
author:
- Akini Ross (@akinross)
options:
  template:
    description:
    - The name of the template.
    - The template must be a Fabric Resource Policy template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the template.
    - The template must be a Fabric Resource Policy template.
    - This parameter or O(template) is required.
    type: str
  name:
    description:
    - The name of the Pod Profile.
    type: str
    aliases: [ pod_profile ]
  uuid:
    description:
    - The UUID of the Pod Profile.
    - This parameter is required when the O(name) needs to be updated.
    type: str
    aliases: [ pod_profile_uuid ]
  description:
    description:
    - The description of the Pod Profile.
    type: str
  pods:
    description:
    - A list of pod IDs to be used in the Pod Profile.
    - When provided, the Pod Profile will apply to pods specified in the range.
    - When an empty list O(pods=[]) is provided, the Pod Profile will apply to all pods.
    - When not provided on initial create, the Pod Profile will apply to all pods.
    type: list
    elements: int
    aliases: [ blocks ]
  pod_settings_uuid:
    description:
    - The UUID of the Pod Settings Policy to be used.
    type: str
  pod_settings:
    description:
    - The reference of the Pod Settings Policy to be used.
    type: dict
    suboptions:
      name:
        description:
        - The name of the Pod Settings Policy.
        type: str
        required: true
      template:
        description:
        - The name of the Pod Settings template.
        - This parameter or O(pod_settings.template_id) is required when O(pod_settings) is used.
        type: str
      template_id:
        description:
        - The ID of the Pod Settings template.
        - This parameter or O(pod_settings.template) is required when O(pod_settings) is used.
        type: str
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Fabric Resource Policy template.
- The O(pod_settings) or O(pod_settings_uuid) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_pod_settings) to create the Pod Settings Policy.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_pod_settings
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a Pod Profile
  cisco.mso.ndo_pod_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_pod_profile
    pod_settings:
      name: ansible_pod_settings
      template: ansible_fabric_policy_template
    state: present
  register: create_pod_profile

- name: Update a Pod Profile using name
  cisco.mso.ndo_pod_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_pod_profile
    pod_settings:
      name: ansible_pod_settings
      template: ansible_fabric_policy_template
    description: Updated Pod Profile
    pods:
      - 1
      - 2
    state: present

- name: Update a Pod Profile using UUID
  cisco.mso.ndo_pod_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_pod_profile_changed
    uuid: "{{ create_pod_profile.current.uuid }}"
    pod_settings_uuid: "{{ create_pod_settings.current.uuid }}"
    state: present

- name: Query a Pod Profile using name
  cisco.mso.ndo_pod_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_pod_profile
    state: query
  register: query_with_name

- name: Query a Pod Profile using UUID
  cisco.mso.ndo_pod_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    uuid: "{{ create_pod_profile.current.uuid }}"
    state: query
  register: query_with_uuid

- name: Query all Pod Profile in a template
  cisco.mso.ndo_pod_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    state: query
  register: query_all_objects

- name: Delete a Pod Profile using Name
  cisco.mso.ndo_pod_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_pod_profile
    state: absent

- name: Delete a Pod Profile using UUID
  cisco.mso.ndo_pod_profile:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: ansible_test
    uuid: "{{ create_pod_profile.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data
import copy

POD_SETTINGS_CACHE = {}


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        name=dict(type="str", aliases=["pod_profile"]),
        uuid=dict(type="str", aliases=["pod_profile_uuid"]),
        description=dict(type="str"),
        pods=dict(type="list", elements="int", aliases=["blocks"]),  # UI uses blocks but chose pods since it is more descriptive
        pod_settings=dict(
            type="dict",
            options=dict(
                name=dict(type="str", required=True),
                template=dict(type="str"),
                template_id=dict(type="str"),
            ),
            required_one_of=[
                ["template", "template_id"],
            ],
            mutually_exclusive=[
                ("template", "template_id"),
            ],
        ),
        pod_settings_uuid=dict(type="str"),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("template", "template_id"),
            ("pod_settings", "pod_settings_uuid"),
        ],
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
            ["state", "present", ["pod_settings", "pod_settings_uuid"], True],
        ],
        required_one_of=[
            ["template", "template_id"],
        ],
    )

    mso = MSOModule(module)
    mso_templates = MSOTemplates(mso)

    template_name = module.params.get("template")
    template_id = module.params.get("template_id")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    pods = module.params.get("pods")
    pod_settings = module.params.get("pod_settings")
    pod_settings_uuid = module.params.get("pod_settings_uuid")
    state = module.params.get("state")

    mso_template = mso_templates.get_template("fabric_resource", template_name, template_id)
    mso_template.validate_template("fabricResource")

    match = mso_template.get_pod_profile_object(uuid, name)

    if (uuid or name) and match:
        set_pod_profile_policy_names(mso, mso_templates, mso_template, match.details)
        mso.existing = mso.previous = copy.deepcopy(match.details)  # Query a specific object
    elif match:
        mso.existing = [set_pod_profile_policy_names(mso, mso_templates, mso_template, obj) for obj in match]  # Query all objects

    pod_profile_path = "/fabricResourceTemplate/template/podProfiles/{0}".format(match.index if match else "-")

    ops = []

    if state == "present":

        mso_values = {
            "name": name,
            "description": description,
        }

        if pods:
            mso_values["blocks"] = pods
            mso_values["kind"] = "podRange"
        elif pods == []:
            mso_values["kind"] = "all"

        if pod_settings_uuid:
            mso_values["policy"] = pod_settings_uuid
        else:
            pod_settings_mso_template = mso_templates.get_template("fabric_policy", pod_settings.get("template"), pod_settings.get("template_id"))
            mso_values["policy"] = pod_settings_mso_template.get_pod_settings_object(
                pod_settings_uuid, pod_settings.get("name"), fail_module=True
            ).details.get("uuid")

        if match:
            remove_data = []
            if pods == []:
                remove_data.append("blocks")

            append_update_ops_data(ops, match.details, pod_profile_path, mso_values, remove_data)
            mso.sanitize(mso_values, collate=True, unwanted=remove_data)
            set_pod_profile_policy_names(mso, mso_templates, mso_template, mso.proposed)
        else:
            if not pods:
                mso_values["kind"] = "all"
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=pod_profile_path, value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=pod_profile_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = mso_template.get_pod_profile_object(uuid, name, search_object=response)
        if match:
            set_pod_profile_policy_names(mso, mso_templates, mso_template, match.details)
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        if mso.proposed:
            set_pod_profile_policy_names(mso, mso_templates, mso_template, mso.proposed)
        mso.existing = mso.proposed if state == "present" else {}
    mso.exit_json()


def set_pod_profile_policy_names(mso, mso_templates, mso_template, pod_profile):

    # TODO: leverage update_config_with_template_and_references when podPolicyGroup type is supported by objects API endpoint
    # "mso/api/v1/templates/objects?type=podPolicyGroup&uuid=0809339e-65f7-4000-a23a-a39241865db8"
    # {
    #   "code": 400,
    #   "message": "unsupported policy type: podPolicyGroup"
    # }
    # reference_dict = {
    #     "policy": {
    #         "name": "pod_settings",
    #         "reference": "policy",
    #         "type": "podPolicyGroup",
    #     }
    # }
    # if pod_profile and pod_profile.get("policy"):
    #     mso_template.update_config_with_template_and_references(pod_profile, reference_dict)

    # Workaround template looping until podPolicyGroup type is supported by objects API endpoint
    # Check if a policy is set in the pod profile, this is the UUID of the pod settings policy

    pod_profile["templateName"] = mso_template.template_name
    pod_profile["templateId"] = mso_template.template_id
    if pod_profile.get("policy"):
        pod_settings_uuid = pod_profile.get("policy")

        # Check if the pod settings UUID is already in the cache
        if pod_settings_uuid in POD_SETTINGS_CACHE:
            pod_profile_details = POD_SETTINGS_CACHE[pod_settings_uuid]
            pod_profile["policyName"] = pod_profile_details.get("policyName")
            pod_profile["policyTemplateName"] = pod_profile_details.get("policyTemplateName")
            pod_profile["policyTemplateId"] = pod_profile_details.get("policyTemplateId")
            return pod_profile

        # Retrieve a summary of all fabric_policy templates from NDO and loop through all templates to find the pod settings policy
        for template in MSOTemplate(mso, "fabric_policy").template:
            for policy in template.get("policies", []):
                # Only retrieve the template details if the fabric_policy template has a pod settings policy defined
                if policy.get("objType") == "podPolicyGroup" and policy.get("count") > 0:
                    pod_settings_mso_template = mso_templates.get_template("fabric_policy", template.get("templateName"), template.get("templateId"))
                    match = pod_settings_mso_template.get_pod_settings_object(pod_settings_uuid)
                    if match:
                        pod_profile["policyName"] = match.details.get("name")
                        pod_profile["policyTemplateName"] = pod_settings_mso_template.template_name
                        pod_profile["policyTemplateId"] = pod_settings_mso_template.template_id
                        POD_SETTINGS_CACHE[pod_settings_uuid] = {
                            "policyName": match.details.get("name"),
                            "policyTemplateName": pod_settings_mso_template.template_name,
                            "policyTemplateId": pod_settings_mso_template.template_id,
                        }
                        return pod_profile


if __name__ == "__main__":
    main()
