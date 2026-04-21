#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_node_group_policy
short_description: Manage L3Out Node Group Policy on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Out Node Group Policy on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the template.
    - The template must be an L3Out template.
    type: str
    aliases: [ l3out_template ]
    required: true
  l3out:
    description:
    - The name of the L3Out.
    type: str
    aliases: [ l3out_name ]
    required: true
  name:
    description:
    - The name of the L3Out Node Group Policy.
    type: str
    aliases: [ l3out_node_group_policy ]
  description:
    description:
    - The description of the L3Out Node Group Policy.
    type: str
  node_routing_policy:
    description:
    - The name of the L3Out Node Routing Policy.
    - Providing an empty string will remove the O(node_routing_policy="") from L3Out Node Group Policy.
    type: str
  bfd:
    description:
    - The Bidirectional Forwarding Detection (BFD) multi-hop configuration of the L3Out Node Group Policy.
    - Providing an empty dictionary will remove the O(bfd={}) from the L3Out Node Group Policy.
    type: dict
    suboptions:
      auth:
        description:
        - The BFD multi-hop authentication of the L3Out Node Group Policy.
        type: str
        choices: [ enabled, disabled ]
        aliases: [ bfd_multi_hop_authentication ]
      key_id:
        description:
        - The BFD multi-hop key ID of the L3Out Node Group Policy.
        type: int
      key:
        description:
        - The BFD multi-hop key of the L3Out Node Group Policy.
        type: str
    aliases: [ bfd_multi_hop ]
  target_dscp:
    description:
    - The DSCP Level of the L3Out Node Group Policy.
    type: str
    choices:
      - af11
      - af12
      - af13
      - af21
      - af22
      - af23
      - af31
      - af32
      - af33
      - af41
      - af42
      - af43
      - cs0
      - cs1
      - cs2
      - cs3
      - cs4
      - cs5
      - cs6
      - cs7
      - expedited_forwarding
      - unspecified
      - voice_admit
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
  Use M(cisco.mso.ndo_template) to create the L3Out template.
- The O(l3out) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_l3out_template) to create the L3Out object under the L3Out template.
- The O(node_routing_policy) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_l3out_node_routing_policy) to create the L3Out Node Routing Policy.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_l3out_template
- module: cisco.mso.ndo_l3out_node_routing_policy
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new L3Out node group policy
  cisco.mso.ndo_l3out_node_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    name: node_group_policy_1
    state: present

- name: Update an existing L3Out node group policy
  cisco.mso.ndo_l3out_node_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    name: node_group_policy_1
    description: "Updated description"
    node_routing_policy: ans_node_policy_group_1
    bfd:
      auth: enabled
      key_id: 1
      key: TestKey
    target_dscp: af11
    state: present

- name: Query an existing L3Out node group policy with name
  cisco.mso.ndo_l3out_node_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    name: node_group_policy_1
    state: query
  register: query_with_name

- name: Query all L3Out node group policy
  cisco.mso.ndo_l3out_node_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    state: query
  register: query_all

- name: Delete an existing L3Out node group policy with name
  cisco.mso.ndo_l3out_node_group_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out
    name: node_group_policy_1
    state: absent
"""

RETURN = r"""
"""


import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import TARGET_DSCP_MAP, ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP
from ansible_collections.cisco.mso.plugins.module_utils.utils import generate_api_endpoint, check_if_all_elements_are_none, append_update_ops_data


def bfd_multi_hop_mso_values(bfd):
    return dict(
        authEnabled=ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(bfd.get("auth")),
        keyID=bfd.get("key_id"),
        key=dict(
            value=bfd.get("key"),
        ),
    )


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True, aliases=["l3out_template"]),
        l3out=dict(type="str", required=True, aliases=["l3out_name"]),
        name=dict(type="str", aliases=["l3out_node_group_policy"]),
        description=dict(type="str"),
        node_routing_policy=dict(type="str"),
        bfd=dict(
            type="dict",
            options=dict(
                auth=dict(type="str", choices=["enabled", "disabled"], aliases=["bfd_multi_hop_authentication"]),
                key_id=dict(type="int"),
                key=dict(type="str", no_log=True),
            ),
            aliases=["bfd_multi_hop"],
        ),
        target_dscp=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    l3out = module.params.get("l3out")
    name = module.params.get("name")
    description = module.params.get("description")
    node_routing_policy = module.params.get("node_routing_policy")
    bfd = module.params.get("bfd")
    target_dscp = TARGET_DSCP_MAP.get(module.params.get("target_dscp"))
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "l3out", template)
    mso_template.validate_template("l3out")

    l3out_object = mso_template.get_l3out_object(name=l3out, fail_module=True)
    l3out_node_group = mso_template.get_l3out_node_group(name, l3out_object.details)

    if name and l3out_node_group:
        mso.existing = copy.deepcopy(l3out_node_group.details)
        mso.previous = copy.deepcopy(l3out_node_group.details)  # Query a specific object
    elif l3out_node_group:
        mso.existing = l3out_node_group  # Query all objects

    if state != "query":
        node_group_policy_path = "/l3outTemplate/l3outs/{0}/nodeGroups/{1}".format(l3out_object.index, l3out_node_group.index if l3out_node_group else "-")

    ops = []

    if state == "present":
        if bfd:
            # True if all elements are None, False otherwise.
            bfd_is_empty = check_if_all_elements_are_none(list(bfd.values()))

        l3out_node_routing_policy_object = None
        if node_routing_policy:
            l3out_node_routing_policy_objects = mso.query_objs(
                generate_api_endpoint(
                    "templates/objects", **{"type": "l3OutNodePolGroup", "tenant-id": mso_template.template_summary.get("tenantId"), "include-common": "true"}
                )
            )
            l3out_node_routing_policy_object = mso_template.get_object_by_key_value_pairs(
                "L3Out Node Routing Policy", l3out_node_routing_policy_objects, [KVPair("name", node_routing_policy)], True
            )

        if mso.existing:
            mso_values = dict()
            mso_values_remove = list()

            if mso.existing.get("bfdMultiHop", {}).get("key", {}).get("ref"):
                mso.existing["bfdMultiHop"]["key"].pop("ref", None)
                mso.previous["bfdMultiHop"]["key"].pop("ref", None)

            mso_values["description"] = description

            if node_routing_policy == "" and mso.existing.get(
                "nodeRoutingPolicyRef"
            ):  # Clear the node routing policy when node_routing_policy is empty string
                mso_values_remove.append("nodeRoutingPolicyRef")
            else:
                mso_values["nodeRoutingPolicyRef"] = l3out_node_routing_policy_object.details.get("uuid") if l3out_node_routing_policy_object else None

            if bfd:
                if bfd_is_empty and mso.existing.get("bfdMultiHop"):
                    mso_values_remove.append("bfdMultiHop")

                elif not bfd_is_empty and not mso.existing.get("bfdMultiHop"):
                    mso_values["bfdMultiHop"] = bfd_multi_hop_mso_values(bfd)

                elif not bfd_is_empty and mso.existing.get("bfdMultiHop"):
                    mso_values[("bfdMultiHop", "authEnabled")] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(bfd.get("auth"))
                    mso_values[("bfdMultiHop", "keyID")] = bfd.get("key_id")

                    if bfd.get("key") is not None:
                        if mso.existing.get("bfdMultiHop", {}).get("key") is not None:
                            mso_values[("bfdMultiHop", "key", "value")] = bfd.get("key")
                        else:
                            mso_values[("bfdMultiHop", "key")] = dict(value=bfd.get("key"))

            mso_values["targetDscp"] = target_dscp

            append_update_ops_data(ops, mso.existing, node_group_policy_path, mso_values, mso_values_remove)
            mso.sanitize(mso.existing, collate=True)
        else:
            mso_values = dict(name=name)
            mso_values["description"] = description

            if l3out_node_routing_policy_object:
                mso_values["nodeRoutingPolicyRef"] = l3out_node_routing_policy_object.details.get("uuid")

            if bfd and not bfd_is_empty:
                mso_values["bfdMultiHop"] = bfd_multi_hop_mso_values(bfd)

            mso_values["targetDscp"] = target_dscp

            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=node_group_policy_path, value=mso_values))

        mso.existing = mso.proposed

    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path=node_group_policy_path))

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        l3out_object = mso_template.get_l3out_object(name=l3out, fail_module=True)
        l3out_node_group = mso_template.get_l3out_node_group(name, l3out_object.details)
        if l3out_node_group:
            mso.existing = l3out_node_group.details  # When the state is present
            if mso.existing.get("bfdMultiHop", {}).get("key", {}).get("ref"):
                mso.existing["bfdMultiHop"]["key"].pop("ref")
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
