#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_pod_settings
version_added: "2.11.0"
short_description: Manage Pod Settings on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Pod Settings on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Akini Ross (@akinross)
options:
  template:
    description:
    - The name of the template.
    - The template must be a Fabric Policy template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the template.
    - The template must be a Fabric Policy template.
    - This parameter or O(template) is required.
    type: str
  name:
    description:
    - The name of the Pod Settings.
    type: str
    aliases: [ pod_settings ]
  uuid:
    description:
    - The UUID of the Pod Settings.
    - This parameter is required when the O(name) needs to be updated.
    type: str
    aliases: [ pod_settings_uuid ]
  description:
    description:
    - The description of the Pod Settings.
    type: str
  macsec_policy:
    description:
    - The MACsec Policy to be used.
    - This parameter is mutually exclusive with O(macsec_policy_uuid).
    - Providing an empty dictionary O(macsec_policy={}) will remove the MACsec Policy from the Pod Settings.
    type: dict
    suboptions:
      name:
        description:
        - The name of the MACsec Policy to be used.
        type: str
  macsec_policy_uuid:
    description:
    - The UUID of the MACsec Policy to be used.
    - Providing an empty string O(macsec_policy_uuid="") will remove the MACsec Policy from the Pod Settings.
    - This parameter is mutually exclusive with O(macsec_policy).
    type: str
  ntp_policy:
    description:
    - The NTP Policy to be used.
    - This parameter is mutually exclusive with O(ntp_policy_uuid).
    - Providing an empty dictionary O(ntp_policy={}) will remove the NTP Policy from the Pod Settings.
    type: dict
    suboptions:
      name:
        description:
        - The name of the NTP Policy to be used.
        type: str
  ntp_policy_uuid:
    description:
    - The UUID of the NTP Policy to be used.
    - Providing an empty string O(ntp_policy_uuid="") will remove the NTP Policy from the Pod Settings.
    - This parameter is mutually exclusive with O(ntp_policy).
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
  Use M(cisco.mso.ndo_template) to create the Fabric Policy template.
- The O(macsec_policy) or O(macsec_policy_uuid) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_macsec_policy) to create the MACsec Policy.
- The O(ntp_policy) or O(ntp_policy_uuid) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_ntp_policy) to create the NTP Policy.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_macsec_policy
- module: cisco.mso.ndo_ntp_policy
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create Pod Settings
  cisco.mso.ndo_pod_settings:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_pod_settings
    state: present
  register: create_pod_settings

- name: Update Pod Settings
  cisco.mso.ndo_pod_settings:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_pod_settings
    description: Updated Pod Settings
    macsec_policy:
      name: ansible_macsec_policy
    ntp_policy:
      name: ansible_ntp_policy
    state: present

- name: Update the Pod Settings using UUID
  cisco.mso.ndo_pod_settings:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    uuid: "{{ create_pod_settings.current.uuid }}"
    macsec_policy_uuid: "{{ create_macsec_policy.current.uuid }}"
    ntp_policy_uuid: "{{ create_ntp_policy.current.uuid }}"
    state: present

- name: Query the Pod Settings using name
  cisco.mso.ndo_pod_settings:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_pod_settings
    state: query
  register: query_with_name

- name: Query the Pod Settings using UUID
  cisco.mso.ndo_pod_settings:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    uuid: "{{ create_pod_settings.current.uuid }}"
    state: query
  register: query_with_uuid

- name: Query all Pod Settings in a template
  cisco.mso.ndo_pod_settings:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    state: query
  register: query_all_objects

- name: Delete the Pod Settings using Name
  cisco.mso.ndo_pod_settings:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_pod_settings
    state: absent

- name: Delete the Pod Settings using UUID
  cisco.mso.ndo_pod_settings:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: ansible_test
    uuid: "{{ create_pod_settings.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data, check_if_all_elements_are_none
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        name=dict(type="str", aliases=["pod_settings"]),
        uuid=dict(type="str", aliases=["pod_settings_uuid"]),
        description=dict(type="str"),
        macsec_policy=dict(
            type="dict",
            options=dict(
                name=dict(type="str"),
            ),
        ),
        macsec_policy_uuid=dict(type="str"),
        ntp_policy=dict(
            type="dict",
            options=dict(
                name=dict(type="str"),
            ),
        ),
        ntp_policy_uuid=dict(type="str"),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("template", "template_id"),
            ("macsec_policy", "macsec_policy_uuid"),
            ("ntp_policy", "ntp_policy_uuid"),
        ],
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
        required_one_of=[
            ["template", "template_id"],
        ],
    )

    mso = MSOModule(module)

    template_name = module.params.get("template")
    template_id = module.params.get("template_id")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    macsec_policy = module.params.get("macsec_policy")
    if macsec_policy is not None and check_if_all_elements_are_none(macsec_policy.values()):
        macsec_policy = {}
    macsec_policy_uuid = module.params.get("macsec_policy_uuid")
    ntp_policy = module.params.get("ntp_policy")
    if ntp_policy is not None and check_if_all_elements_are_none(ntp_policy.values()):
        ntp_policy = {}
    ntp_policy_uuid = module.params.get("ntp_policy_uuid")
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "fabric_policy", template_name, template_id)
    mso_template.validate_template("fabricPolicy")
    object_description = "Pod Settings"

    match = mso_template.get_pod_settings_object(uuid, name)

    if (uuid or name) and match:
        set_pod_settings_policy_names(mso_template, match.details)
        mso.existing = mso.previous = copy.deepcopy(match.details)  # Query a specific object
    elif match:
        mso.existing = [set_pod_settings_policy_names(mso_template, obj) for obj in match]  # Query all objects

    pod_settings_path = "/fabricPolicyTemplate/template/podPolicyGroups/{0}".format(match.index if match else "-")

    ops = []

    if state == "present":

        mso_values = {
            "name": name,
            "description": description,
        }

        if macsec_policy or macsec_policy_uuid:
            mso_values["fabricMACsec"] = mso_template.get_macsec_policy_object(
                macsec_policy_uuid,
                macsec_policy.get("name") if macsec_policy else macsec_policy,
                fail_module=True,
            ).details.get("uuid")
        if ntp_policy or ntp_policy_uuid:
            mso_values["ntp"] = mso_template.get_ntp_policy_object(
                ntp_policy_uuid,
                ntp_policy.get("name") if ntp_policy else ntp_policy,
                fail_module=True,
            ).details.get("uuid")

        if match:
            remove_data = []
            unwanted = []
            if macsec_policy == {} or macsec_policy_uuid == "":
                remove_data.append("fabricMACsec")
                unwanted.extend(["fabricMACsec", "fabricMACsecName"])
            if ntp_policy == {} or ntp_policy_uuid == "":
                remove_data.append("ntp")
                unwanted.extend(["ntp", "ntpName"])

            append_update_ops_data(ops, match.details, pod_settings_path, mso_values, remove_data)
            mso.sanitize(mso_values, collate=True, unwanted=unwanted)
            set_pod_settings_policy_names(mso_template, mso.proposed)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=pod_settings_path, value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=pod_settings_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = mso_template.get_pod_settings_object(uuid, name, search_object=response)
        if match:
            set_pod_settings_policy_names(mso_template, match.details)
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        if mso.proposed:
            set_pod_settings_policy_names(mso_template, mso.proposed)
        mso.existing = mso.proposed if state == "present" else {}
    mso.exit_json()


def set_pod_settings_policy_names(mso_template, pod_settings):
    pod_settings["templateName"] = mso_template.template_name
    pod_settings["templateId"] = mso_template.template_id
    if pod_settings.get("fabricMACsec"):
        pod_settings["fabricMACsecName"] = mso_template.get_macsec_policy_object(uuid=pod_settings["fabricMACsec"]).details.get("name")
    if pod_settings.get("ntp"):
        pod_settings["ntpName"] = mso_template.get_ntp_policy_object(uuid=pod_settings["ntp"]).details.get("name")
    return pod_settings


if __name__ == "__main__":
    main()
