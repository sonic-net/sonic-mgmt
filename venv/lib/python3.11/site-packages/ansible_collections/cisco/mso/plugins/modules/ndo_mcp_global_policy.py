#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Samita Bhattacharjee (@samiib) <samitab@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_mcp_global_policy
short_description: Manage the MCP Global Policy in a Fabric Policy Template on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage the MisCabling Protocol (MCP) Global Policy in a Fabric Policy Template on Cisco Nexus Dashboard Orchestrator (NDO).
- There can only be a single MCP Global Policy in a Fabric Policy Template.
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Samita Bhattacharjee (@samiib)
options:
  template:
    description:
    - The name of the template.
    - The template must be a Fabric Policy template.
    type: str
    aliases: [ fabric_template ]
    required: true
  name:
    description:
    - The name of the MCP Global Policy.
    type: str
    aliases: [ mcp_global_policy ]
  uuid:
    description:
    - The UUID of the MCP Global Policy.
    type: str
    aliases: [ mcp_global_policy_uuid ]
  description:
    description:
    - The description of the MCP Global Policy.
    - Providing an empty string will remove the O(description="") from the MCP Global Policy.
    type: str
  admin_state:
    description:
    - The administrative state of the MCP Global Policy.
    - Defaults to C(enabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
  key:
    description:
    - The key of the MCP Global Policy.
    type: str
  per_vlan:
    description:
    - When enabled MCP will send packets on a per End Point Group (EPG) basis.
    - If disabled, the packets will only be sent on untagged EPGs which allows detecting loops in the native VLAN only.
    - Defaults to C(disabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
    aliases: [ per_epg, mcp_pdu_per_vlan ]
  loop_detection_factor:
    description:
    - The amount of MCP packets that will be received before port disable loop protection action takes place.
    - Defaults to 3 when unset during creation.
    - The value must be between 1 and 255.
    type: int
    aliases: [ loop_factor, loop_detection_mult_factor ]
  port_disable:
    description:
    - Enable or disable port disabling when MCP packets are received.
    - Defaults to C(enabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
    aliases: [ port_disable_protection ]
  initial_delay_time:
    description:
    - The MCP initial delay time in seconds.
    - Defaults to 180 when unset during creation.
    - The value must be between 0 and 1800.
    type: int
    aliases: [ initial_delay ]
  transmission_frequency_sec:
    description:
    - The MCP transmission frequency in seconds.
    - Defaults to 2 when unset during creation.
    - The value must be between 0 and 300.
    type: int
    aliases: [ tx_freq ]
  transmission_frequency_msec:
    description:
    - The MCP transmission frequency in milliseconds.
    - Defaults to 0 when unset during creation.
    - The value must be between 0 and 999.
    type: int
    aliases: [ tx_freq_ms ]
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
- Attempts to create any additional MCP Global Policies will only update the existing
  object in the Fabric Policy template.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create the MCP Global Policy object
  cisco.mso.ndo_mcp_global_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_template
    name: example_mcp_global_policy
    state: present
  register: mcp_global_policy_new

- name: Create the MCP Global Policy object with all attributes
  cisco.mso.ndo_mcp_global_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_template
    name: example_mcp_global_policy
    description: A Global MCP Policy
    key: cisco
    admin_state: enabled
    per_vlan: enabled
    loop_detection_factor: 3
    port_disable: enabled
    initial_delay_time: 180
    transmission_frequency_sec: 2
    transmission_frequency_msec: 10
    state: present
  register: mcp_global_policy_all

- name: Update the MCP Global Policy object with UUID
  cisco.mso.ndo_mcp_global_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_template
    name: mcp_global_policy_update
    uuid: "{{ mcp_global_policy_all.current.uuid }}"
    state: present

- name: Query the MCP Global Policy object with name
  cisco.mso.ndo_mcp_global_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_template
    name: example_mcp_global_policy
    state: query
  register: query_name

- name: Query the MCP Global Policy object with UUID
  cisco.mso.ndo_mcp_global_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_template
    uuid: "{{ mcp_global_policy_all.current.uuid }}"
    state: query
  register: query_uuid

- name: Query the MCP Global Policy object in a Fabric Template
  cisco.mso.ndo_mcp_global_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_template
    state: query
  register: query_all

- name: Delete the MCP Global Policy object with name
  cisco.mso.ndo_mcp_global_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_template
    name: example_mcp_global_policy
    state: absent

- name: Delete the MCP Global Policy object with UUID
  cisco.mso.ndo_mcp_global_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: fabric_template
    uuid: "{{ mcp_global_policy_all.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.constants import ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True, aliases=["fabric_template"]),
        name=dict(type="str", aliases=["mcp_global_policy"]),
        uuid=dict(type="str", aliases=["mcp_global_policy_uuid"]),
        description=dict(type="str"),
        admin_state=dict(type="str", choices=["enabled", "disabled"]),
        key=dict(type="str", no_log=False),
        per_vlan=dict(
            type="str",
            aliases=["per_epg", "mcp_pdu_per_vlan"],
            choices=["enabled", "disabled"],
        ),
        loop_detection_factor=dict(type="int", aliases=["loop_factor", "loop_detection_mult_factor"]),
        port_disable=dict(
            type="str",
            aliases=["port_disable_protection"],
            choices=["enabled", "disabled"],
        ),
        initial_delay_time=dict(type="int", aliases=["initial_delay"]),
        transmission_frequency_sec=dict(type="int", aliases=["tx_freq"]),
        transmission_frequency_msec=dict(type="int", aliases=["tx_freq_ms"]),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    # Enforcing that a user must specify a name or uuid when
    # adding, updating or removing even though there is only one policy per template.
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
    )

    mso = MSOModule(module)

    name = module.params.get("name")
    uuid = module.params.get("uuid")
    state = module.params.get("state")
    per_vlan = module.params.get("per_vlan")
    port_disable = module.params.get("port_disable")

    mso_values = {
        "name": name,
        "description": module.params.get("description"),
        "adminState": module.params.get("admin_state"),
        "key": module.params.get("key"),
        "enablePduPerVlan": ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(per_vlan),
        "loopDetectMultFactor": module.params.get("loop_detection_factor"),
        "protectPortDisable": ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(port_disable),
        "initialDelayTime": module.params.get("initial_delay_time"),
        "txFreq": module.params.get("transmission_frequency_sec"),
        "txFreqMsec": module.params.get("transmission_frequency_msec"),
    }

    ops = []

    mso_template = MSOTemplate(mso, "fabric_policy", module.params.get("template"))
    mso_template.validate_template("fabricPolicy")

    object_description = "MCP Global Policy"
    object_base_path = "/fabricPolicyTemplate/template/mcpGlobalPolicy"

    existing_mcp_global_policy = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {}).get("mcpGlobalPolicy", {})

    if state in ["query", "absent"] and existing_mcp_global_policy == {}:
        mso.exit_json()

    elif state == "query" and not (name or uuid):
        mso.existing = [existing_mcp_global_policy]

    elif existing_mcp_global_policy and (name or uuid):
        mso.existing = mso.previous = copy.deepcopy(existing_mcp_global_policy)
        if uuid and mso.existing.get("uuid") != uuid:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

    if state == "present":
        if mso.existing:
            proposed_payload = copy.deepcopy(mso.existing)
            append_update_ops_data(ops, proposed_payload, object_base_path, mso_values)
            mso.sanitize(proposed_payload, collate=True)
        else:
            if uuid:
                mso.fail_json(msg="{0} cannot be created with a UUID".format(object_description))
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=object_base_path, value=mso.sent))

        mso.existing = mso.proposed

    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path=object_base_path))

    if not module.check_mode and ops:
        response_object = mso.request(mso_template.template_path, method="PATCH", data=ops)
        mso.existing = response_object.get("fabricPolicyTemplate", {}).get("template", {}).get("mcpGlobalPolicy", {})
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
