#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_synce_interface_policy
short_description: Manage syncE Interface Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage syncE Interface Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Anvitha Jain (@anvjain)
options:
  template:
    description:
    - The name of the template.
    - The template must be a fabric policy template.
    type: str
    required: true
  interface_policy:
    description:
    - The name of the syncE Interface Policy.
    type: str
    aliases: [ name ]
  interface_policy_uuid:
    description:
    - The uuid of the syncE Interface Policy.
    - This parameter is required when the O(interface_policy) needs to be updated.
    type: str
    aliases: [ uuid ]
  description:
    description:
    - The description of the syncE Interface Policy.
    type: str
  admin_state:
    description:
    - The administrative state of the syncE Interface Policy.
    - The default value is disabled.
    type: str
    choices: [ enabled, disabled ]
  sync_state_msg:
    description:
    - The sync state message of the syncE Interface Policy.
    - The default value is enabled.
    type: str
    choices: [ enabled, disabled ]
  selection_input:
    description:
    - The selection input of the syncE Interface Policy.
    - The default value is disabled.
    type: str
    choices: [ enabled, disabled ]
  src_priority:
    description:
    - The source priority of the syncE Interface Policy.
    - The value must be an integer between 1 and 254.
    - The default value is 100.
    type: int
  wait_to_restore:
    description:
    - The delay before attempting to restore synchronization on a SyncE interface after a disruption.
    - The value must be an integer between 0 and 12.
    - The default value is 5.
    type: int
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new syncE interface policy
  cisco.mso.ndo_synce_interface_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    interface_policy: ansible_test_interface_policy
    admin_state: enabled
    sync_state_msg: enabled
    selection_input: enabled
    src_priority: 100
    wait_to_restore: 5
    state: present
  register: create

- name: Query a syncE interface policy with interface_policy name
  cisco.mso.ndo_synce_interface_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    interface_policy: ansible_test_interface_policy
    state: query
  register: query_one

- name: Query all syncE interface policies in the template
  cisco.mso.ndo_synce_interface_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    state: query
  register: query_all

- name: Query a syncE interface policy with interface_policy UUID
  cisco.mso.ndo_synce_interface_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    interface_policy_uuid: '{{ create.current.uuid }}'
    state: query
  register: query_one_by_uuid

- name: Delete a syncE interface policy
  cisco.mso.ndo_synce_interface_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_policy_template
    interface_policy: ansible_test_interface_policy
    state: absent
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dict(
            template=dict(type="str", required=True),
            interface_policy=dict(type="str", aliases=["name"]),
            interface_policy_uuid=dict(type="str", aliases=["uuid"]),
            description=dict(type="str"),
            admin_state=dict(type="str", choices=["enabled", "disabled"]),
            sync_state_msg=dict(type="str", choices=["enabled", "disabled"]),
            selection_input=dict(type="str", choices=["enabled", "disabled"]),
            src_priority=dict(type="int"),
            wait_to_restore=dict(type="int"),
            state=dict(type="str", choices=["absent", "query", "present"], default="query"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["interface_policy"]],
            ["state", "absent", ["interface_policy"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    interface_policy = module.params.get("interface_policy")
    interface_policy_uuid = module.params.get("interface_policy_uuid")
    description = module.params.get("description")
    admin_state = module.params.get("admin_state")
    sync_state_msg = module.params.get("sync_state_msg")
    selection_input = module.params.get("selection_input")
    src_priority = module.params.get("src_priority")
    wait_to_restore = module.params.get("wait_to_restore")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_policy", template)
    mso_template.validate_template("fabricPolicy")

    path = "/fabricPolicyTemplate/template/syncEthIntfPolicies"
    match = get_synce_interface_policy(mso_template, interface_policy_uuid, interface_policy)

    if interface_policy_uuid or interface_policy:
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)  # Query a specific object
    elif match:
        mso.existing = match  # Query all objects

    if state == "present":
        mso.existing = {}

        if match:
            sync_state_msg_value = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(sync_state_msg)
            selection_input_value = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(selection_input)

            if interface_policy and match.details.get("name") != interface_policy:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=interface_policy))
                match.details["name"] = interface_policy

            if description is not None and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            if admin_state and match.details.get("adminState") != admin_state:
                ops.append(dict(op="replace", path="{0}/{1}/adminState".format(path, match.index), value=admin_state))
                match.details["adminState"] = admin_state

            if sync_state_msg and match.details.get("syncStateMsgEnabled") != sync_state_msg_value:
                ops.append(dict(op="replace", path="{0}/{1}/syncStateMsgEnabled".format(path, match.index), value=sync_state_msg_value))
                match.details["syncStateMsgEnabled"] = sync_state_msg_value

            if selection_input and match.details.get("selectionInputEnabled") != selection_input_value:
                ops.append(dict(op="replace", path="{0}/{1}/selectionInputEnabled".format(path, match.index), value=selection_input_value))
                match.details["selectionInputEnabled"] = selection_input_value

            if src_priority and match.details.get("srcPriority") != src_priority:
                ops.append(dict(op="replace", path="{0}/{1}/srcPriority".format(path, match.index), value=src_priority))
                match.details["srcPriority"] = src_priority

            if wait_to_restore and match.details.get("waitToRestore") != wait_to_restore:
                ops.append(dict(op="replace", path="{0}/{1}/waitToRestore".format(path, match.index), value=wait_to_restore))
                match.details["waitToRestore"] = wait_to_restore

            mso.sanitize(match.details)

        else:
            payload = {"name": interface_policy, "templateId": mso_template.template.get("templateId"), "schemaId": mso_template.template.get("schemaId")}
            if description:
                payload["description"] = description
            if admin_state:
                payload["adminState"] = admin_state
            if sync_state_msg:
                payload["syncStateMsgEnabled"] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(sync_state_msg)
            if selection_input:
                payload["selectionInputEnabled"] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(selection_input)
            if src_priority:
                payload["srcPriority"] = src_priority
            if wait_to_restore:
                payload["waitToRestore"] = wait_to_restore

            ops.append(dict(op="add", path="{0}/-".format(path), value=copy.deepcopy(payload)))

            mso.sanitize(payload)

        mso.existing = mso.proposed

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))
        mso.existing = {}

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = get_synce_interface_policy(mso_template, interface_policy_uuid, interface_policy)
        if match:
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def get_synce_interface_policy(mso_template, uuid=None, name=None, fail_module=False):
    """
    Get the SyncE Interface Policy by UUID or Name.
    :param uuid: UUID of the SyncE Interface Policy to search for -> Str
    :param name: Name of the SyncE Interface Policy to search for -> Str
    :param fail_module: When match is not found fail the ansible module -> Bool
    :return: Dict | None | List[Dict] | List[]: The processed result which could be:
              When the UUID | Name is existing in the search list -> Dict
              When the UUID | Name is not existing in the search list -> None
              When both UUID and Name are None, and the search list is not empty -> List[Dict]
              When both UUID and Name are None, and the search list is empty -> List[]
    """
    match = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {}).get("syncEthIntfPolicies", [])
    if uuid or name:  # Query a specific object
        return mso_template.get_object_by_key_value_pairs(
            "SyncE Interface Policy", match, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module
        )
    return match  # Query all objects


if __name__ == "__main__":
    main()
