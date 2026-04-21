#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_ptp_policy_profiles
short_description: Manage PTP Policy Profiles on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage PTP Policy Profiles on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Shreyas Srish (@shrsr)
options:
  template:
    description:
    - The name of the template.
    - The template must be a fabric policy template.
    type: str
    required: true
  ptp_policy_profile_name:
    description:
    - The name of the PTP Policy profile.
    type: str
    aliases: [ name ]
  ptp_policy_profile_uuid:
    description:
    - The UUID of the PTP Policy profile.
    type: str
    aliases: [ uuid ]
  delay_interval:
    description:
    - Delay interval of the PTP Policy profile.
    - The value should be between -4 to 4.
    - This is required when O(state=present).
    type: int
  profile_template:
    description:
    - Profile template of the PTP Policy profile.
    - The default value is aes67_2015.
    type: str
    choices: [ aes67_2015, default, telecom_8275_1, smpte_2059_2 ]
  sync_interval:
    description:
    - Sync interval of the PTP Policy profile.
    - The value should be between -4 to -1.
    - This is required when O(state=present).
    type: int
  override_node_profile:
    description:
    - Node profile override of the PTP Policy profile.
    type: bool
  announce_timeout:
    description:
    - Announce timeout of the PTP Policy profile.
    - The value should be between 2 to 10.
    - This is required when O(state=present).
    type: int
  announce_interval:
    description:
    - Announce interval of the PTP Policy profile.
    - The value should be between -3 to 1.
    - This is required when O(state=present).
    type: int
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) and ptp_policy object must exist before using this module in your playbook.
  The M(cisco.mso.ndo_template) and M(cisco.mso.ndo_ptp_policy) modules can be used for this.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_ptp_policy
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new PTP profile
  cisco.mso.ndo_ptp_policy_profiles:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    ptp_policy_profile_name: ansible_profile
    delay_interval: 2
    sync_interval: 1
    announce_timeout: 3
    announce_interval: 4
    profile_template: aes67_2015
    state: present
  register: create_ptp_profile

- name: Query a PTP profile
  cisco.mso.ndo_ptp_policy_profiles:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    ptp_policy_profile_name: ansible_profile
    state: query
  register: query_one

- name: Query a PTP profile using UUID
  cisco.mso.ndo_ptp_policy_profiles:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    ptp_policy_profile_uuid: "{{ create_ptp_profile.current.uuid }}"
    state: query
  register: query_one_uuid

- name: Query all PTP profiles
  cisco.mso.ndo_ptp_policy_profiles:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    state: query
  register: query_all

- name: Update a PTP profile name with UUID
  cisco.mso.ndo_ptp_policy_profiles:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    ptp_policy_profile_name: profile_update
    ptp_policy_profile_uuid: "{{ create_ptp_profile.current.uuid }}"

- name: Delete a PTP profile using name
  cisco.mso.ndo_ptp_policy_profiles:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    ptp_policy_profile_name: ansible_profile
    state: absent

- name: Delete a PTP profile using UUID
  cisco.mso.ndo_ptp_policy_profiles:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    ptp_policy_profile_uuid: "{{ create_ptp_profile.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data
from ansible_collections.cisco.mso.plugins.module_utils.constants import PROFILE_TEMPLATE
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dict(
            template=dict(type="str", required=True),
            ptp_policy_profile_name=dict(type="str", aliases=["name"]),
            ptp_policy_profile_uuid=dict(type="str", aliases=["uuid"]),
            delay_interval=dict(type="int"),
            profile_template=dict(type="str", choices=list(PROFILE_TEMPLATE)),
            sync_interval=dict(type="int"),
            override_node_profile=dict(type="bool"),
            announce_timeout=dict(type="int"),
            announce_interval=dict(type="int"),
            state=dict(type="str", choices=["absent", "query", "present"], default="query"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["ptp_policy_profile_name", "ptp_policy_profile_uuid"], True],
            ["state", "absent", ["ptp_policy_profile_name", "ptp_policy_profile_uuid"], True],
            ["state", "present", ["announce_interval", "announce_timeout", "sync_interval", "delay_interval"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    ptp_policy_profile_name = module.params.get("ptp_policy_profile_name")
    ptp_policy_profile_uuid = module.params.get("ptp_policy_profile_uuid")
    delay_interval = module.params.get("delay_interval")
    profile_template = PROFILE_TEMPLATE.get(module.params.get("profile_template"))
    sync_interval = module.params.get("sync_interval")
    override_node_profile = module.params.get("override_node_profile")
    announce_timeout = module.params.get("announce_timeout")
    announce_interval = module.params.get("announce_interval")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_policy", template)
    mso_template.validate_template("fabricPolicy")
    object_description = "Profiles"

    path = "/fabricPolicyTemplate/template/ptpPolicy/profiles"

    existing_profiles = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {}).get("ptpPolicy", {}).get("profiles") or []

    if ptp_policy_profile_name or ptp_policy_profile_uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_profiles,
            [KVPair("uuid", ptp_policy_profile_uuid) if ptp_policy_profile_uuid else KVPair("name", ptp_policy_profile_name)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_profiles

    if state == "present":
        mso_values = dict(
            name=ptp_policy_profile_name,
            delayIntvl=delay_interval,
            profileTemplate=profile_template,
            syncIntvl=sync_interval,
            nodeProfileOverride=override_node_profile,
            announceTimeout=announce_timeout,
            announceIntvl=announce_interval,
        )

        if match:
            update_path = "{0}/{1}".format(path, match.index)
            append_update_ops_data(ops, match.details, update_path, mso_values)
            mso.sanitize(match.details, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="{0}/-".format(path), value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        profiles = response.get("fabricPolicyTemplate", {}).get("template", {}).get("ptpPolicy", {}).get("profiles") or []
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            profiles,
            [KVPair("uuid", ptp_policy_profile_uuid) if ptp_policy_profile_uuid else KVPair("name", ptp_policy_profile_name)],
        )
        if match:
            mso.existing = match.details
        else:
            mso.existing = {}
    elif module.check_mode and state != "query":
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
