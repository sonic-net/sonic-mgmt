#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_ptp_policy
short_description: Manage PTP Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Precision Time Protocol (PTP) Policies on Cisco Nexus Dashboard Orchestrator (NDO).
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
  ptp_policy:
    description:
    - The name of the PTP policy.
    type: str
    aliases: [ name ]
  ptp_policy_uuid:
    description:
    - The UUID of the PTP policy.
    - This parameter is required when the O(ptp_policy) needs to be updated.
    type: str
    aliases: [ uuid ]
  description:
    description:
    - The description of the PTP Policy.
    type: str
  admin_state:
    description:
    - The administrative state of the PTP Policy.
    type: str
    choices: [ enabled, disabled ]
  fabric_sync_interval:
    description:
    - Fabric synchronization interval for the PTP Policy.
    - The value should be between -4 to 1.
    - This is required when O(state=present).
    type: int
  global_domain:
    description:
    - Global domain number for the PTP Policy.
    - The value should be between 1 to 128.
    - This is required when O(state=present).
    type: int
  fabric_delay_interval:
    description:
    - Fabric delay interval for the PTP policy.
    - The value should be between -3 to 5.
    - This is required when O(state=present).
    type: int
  global_priority1:
    description:
    - Priority 1 for the PTP Policy.
    - The value should be between 1 to 255.
    - This is required when O(state=present).
    type: int
  global_priority2:
    description:
    - Priority 2 for the PTP Policy.
    - The value should be between 1 to 255.
    - This is required when O(state=present).
    type: int
  fabric_announce_timeout:
    description:
    - Fabric announce timeout for the PTP policy.
    - The value should be between 2 to 10.
    - This is required when O(state=present).
    type: int
  fabric_announce_interval:
    description:
    - Fabric announce interval for the PTP policy.
    - The value should be between 0 to 4.
    - This is required when O(state=present).
    type: int
  fabric_profile_template:
    description:
    - Fabric profile template for the PTP policy.
    type: str
    choices: [ aes67_2015, default, smpte_2059_2 ]
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
  The M(cisco.mso.ndo_template) module can be used for this.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new PTP policy
  cisco.mso.ndo_ptp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    ptp_policy: ansible_test_ptp_policy
    admin_state: enabled
    fabric_sync_interval: -3
    global_domain: 0
    fabric_delay_interval: -2
    global_priority1: 255
    global_priority2: 255
    fabric_announce_timeout: 3
    fabric_announce_interval: 1
    fabric_profile_template: aes67_2015
    state: present
  register: create_ptp

- name: Query a PTP policy with ptp_policy name
  cisco.mso.ndo_ptp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    ptp_policy: ansible_test_ptp_policy
    state: query
  register: query_one

- name: Query a PTP policy with ptp_policy UUID
  cisco.mso.ndo_ptp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    ptp_policy_uuid: "{{ create_ptp.current.uuid }}"
    state: query
  register: query_one_uuid

- name: Update a PTP policy name with UUID
  cisco.mso.ndo_ptp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    ptp_policy: ansible_test_ptp_policy_updated
    ptp_policy_uuid: "{{ create_ptp.current.uuid }}"
    state: present

- name: Delete a PTP policy
  cisco.mso.ndo_ptp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_ptp_policy_updated
    ptp_policy: ansible_test_ptp_policy
    state: absent

- name: Delete a PTP policy using UUID
  cisco.mso.ndo_ptp_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    ptp_policy_uuid: "{{ query_one.current.uuid }}"
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
            ptp_policy=dict(type="str", aliases=["name"]),
            ptp_policy_uuid=dict(type="str", aliases=["uuid"]),
            description=dict(type="str"),
            admin_state=dict(type="str", choices=["enabled", "disabled"]),
            fabric_sync_interval=dict(type="int"),
            global_domain=dict(type="int"),
            fabric_delay_interval=dict(type="int"),
            global_priority1=dict(type="int"),
            global_priority2=dict(type="int"),
            fabric_announce_timeout=dict(type="int"),
            fabric_announce_interval=dict(type="int"),
            fabric_profile_template=dict(type="str", choices=["aes67_2015", "default", "smpte_2059_2"]),
            state=dict(type="str", choices=["absent", "query", "present"], default="query"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["ptp_policy", "ptp_policy_uuid"], True],
            ["state", "absent", ["ptp_policy", "ptp_policy_uuid"], True],
            [
                "state",
                "present",
                [
                    "global_priority1",
                    "global_priority2",
                    "global_domain",
                    "fabric_announce_timeout",
                    "fabric_announce_interval",
                    "fabric_sync_interval",
                    "fabric_delay_interval",
                ],
            ],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    ptp_policy = module.params.get("ptp_policy")
    ptp_policy_uuid = module.params.get("ptp_policy_uuid")
    description = module.params.get("description")
    admin_state = module.params.get("admin_state")
    fabric_sync_interval = module.params.get("fabric_sync_interval")
    global_domain = module.params.get("global_domain")
    fabric_delay_interval = module.params.get("fabric_delay_interval")
    global_priority1 = module.params.get("global_priority1")
    global_priority2 = module.params.get("global_priority2")
    fabric_announce_timeout = module.params.get("fabric_announce_timeout")
    fabric_announce_interval = module.params.get("fabric_announce_interval")
    fabric_profile_template = PROFILE_TEMPLATE.get(module.params.get("fabric_profile_template"))
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_policy", template)
    mso_template.validate_template("fabricPolicy")
    object_description = "PTP Policy"

    path = "/fabricPolicyTemplate/template/ptpPolicy"

    existing_ptp_policies = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {}).get("ptpPolicy", {})

    if ptp_policy or ptp_policy_uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            [existing_ptp_policies],
            [KVPair("uuid", ptp_policy_uuid) if ptp_policy_uuid else KVPair("name", ptp_policy)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_ptp_policies

    if state == "present":
        if match:
            mso_values_update = {
                "name": ptp_policy,
                "description": description,
                ("global", "adminState"): admin_state,
                ("global", "fabSyncIntvl"): fabric_sync_interval,
                ("global", "globalDomain"): global_domain,
                ("global", "fabDelayIntvl"): fabric_delay_interval,
                ("global", "prio1"): global_priority1,
                ("global", "prio2"): global_priority2,
                ("global", "fabAnnounceTimeout"): fabric_announce_timeout,
                ("global", "fabAnnounceIntvl"): fabric_announce_interval,
                ("global", "fabProfileTemplate"): fabric_profile_template,
            }
            append_update_ops_data(ops, match.details, path, mso_values_update)
            mso.sanitize(match.details, collate=True)
        else:
            mso_values = {
                "name": ptp_policy,
                "description": description,
                "global": {
                    "adminState": admin_state,
                    "fabSyncIntvl": fabric_sync_interval,
                    "globalDomain": global_domain,
                    "fabDelayIntvl": fabric_delay_interval,
                    "prio1": global_priority1,
                    "prio2": global_priority2,
                    "fabAnnounceTimeout": fabric_announce_timeout,
                    "fabAnnounceIntvl": fabric_announce_interval,
                    "fabProfileTemplate": fabric_profile_template,
                },
            }
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="{0}".format(path), value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}".format(path)))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        ptp_policies = response.get("fabricPolicyTemplate", {}).get("template", {}).get("ptpPolicy", {})
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            [ptp_policies],
            [KVPair("uuid", ptp_policy_uuid) if ptp_policy_uuid else KVPair("name", ptp_policy)],
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
