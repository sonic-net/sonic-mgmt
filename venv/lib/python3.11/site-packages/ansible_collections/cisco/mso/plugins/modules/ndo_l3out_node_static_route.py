#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_node_static_route
version_added: "2.11.0"
short_description: Manage L3Out Node Static Routes on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Out Node Static Routes on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Akini Ross (@akinross)
options:
  template:
    description:
    - The name of the template.
    - The template must be an L3Out template.
    - This parameter or O(template_id) is required.
    type: str
    aliases: [ l3out_template ]
  template_id:
    description:
    - The ID of the L3Out template.
    - This parameter or O(template) is required.
    type: str
    aliases: [ l3out_template_id ]
  l3out:
    description:
    - The name of the L3Out.
    - This parameter or O(l3out_uuid) is required.
    type: str
    aliases: [ l3out_name ]
  l3out_uuid:
    description:
    - The UUID of the L3Out.
    - This parameter or O(l3out) is required.
    type: str
  pod_id:
    description:
    - The pod ID of the node (border leaf switch).
    type: str
    required: true
    aliases: [ pod ]
  node_id:
    description:
    - The ID of the node.
    type: str
    required: true
    aliases: [ node, border_leaf ]
  prefix:
    description:
    - The prefix of the static route.
    type: str
  description:
    description:
    - The description of the static route.
    - Providing an empty string O(description="") will remove the description from the static route.
    type: str
  administrative_distance:
    description:
    - The administrative distance of the static route.
    - The value must be in the range 1 - 255.
    - Defaults to O(administrative_distance=1) when unset during creation.
    type: int
    aliases: [ admin_distance ]
  bfd_tracking:
    description:
    - Enable BFD tracking for the static route.
    - Defaults to O(bfd_tracking=false) when unset during creation.
    type: bool
  next_hop_null:
    description:
    - Create a static route to Null0 interface.
    - This is used to drop traffic for the specified prefix.
    - Defaults to O(next_hop_null=false) when unset during creation.
    type: bool
  track_policy_uuid:
    description:
    - The UUID of the track policy to be used.
    - Providing an empty string O(track_policy="") will remove the track policy from the static route.
    type: str
    aliases: [ ipsla_track_list_uuid ]
  track_policy:
    description:
    - The track policy to be used.
    - Providing an empty dictionary O(track_policy={}) will remove the track policy from the static route.
    type: dict
    aliases: [ ipsla_track_list ]
    suboptions:
      name:
        description:
        - The name of the track policy.
        type: str
      template:
        description:
        - The name of the template that contains the track policy.
        - This parameter or O(track_policy.template_id) is required.
        type: str
      template_id:
        description:
        - The ID of the template that contains the track policy.
        - This parameter or O(track_policy.template) is required.
        type: str
  state:
    description:
    - Determines the desired state of the resource.
    - Use C(absent) to remove the resource.
    - Use C(query) to list the resource.
    - Use C(present) to create or update the resource.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) or O(template_id) must exist before using this module in your playbook.
  The M(cisco.mso.ndo_template) module can be used for this.
- The O(l3out) or O(l3out_uuid) must exist before using this module in your playbook.
  The M(cisco.mso.ndo_l3out_template) module can be used for this.
- The O(track_policy) or O(track_policy_uuid) must exist before using this module in your playbook.
  The M(cisco.mso.ndo_ipsla_track_list) module can be used for this.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_l3out_template
- module: cisco.mso.ndo_ipsla_track_list
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a L3Out Node Static Route
  cisco.mso.ndo_l3out_node_static_route:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    pod_id: 1
    node_id: 101
    prefix: 10.0.0.0/24
    state: present

- name: Update an existing L3Out Node Static Route
  cisco.mso.ndo_l3out_node_static_route:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: "{{ l3out_template.current.templateId }}"
    l3out_uuid: "{{ l3out.current.uuid }}"
    pod_id: 1
    node_id: 101
    prefix: 10.0.0.0/24
    description: "Static route for 10.0.0.0/24"
    administrative_distance: 10
    bfd_tracking: true
    next_hop_null: true
    track_policy:
      name: "track_policy_name"
      template: "track_policy_template"
    state: present

- name: Query an existing L3Out Node Static Route
  cisco.mso.ndo_l3out_node_static_route:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    pod_id: 1
    node_id: 101
    prefix: 10.0.0.0/24
    state: query
  register: query_with_name

- name: Query all existing L3Out Node Static Routes in a L3Out Node
  cisco.mso.ndo_l3out_node_static_route:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    pod_id: 1
    node_id: 101
    state: query

- name: Delete an existing L3Out Node Static Route
  cisco.mso.ndo_l3out_node_static_route:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    pod_id: 1
    node_id: 101
    prefix: 10.0.0.0/24
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data, check_if_all_elements_are_none
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", aliases=["l3out_template"]),
        template_id=dict(type="str", aliases=["l3out_template_id"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        l3out_uuid=dict(type="str"),
        pod_id=dict(type="str", aliases=["pod"], required=True),
        node_id=dict(type="str", aliases=["node", "border_leaf"], required=True),
        prefix=dict(type="str"),
        description=dict(type="str"),
        administrative_distance=dict(type="int", aliases=["admin_distance"]),
        bfd_tracking=dict(type="bool"),
        next_hop_null=dict(type="bool"),
        track_policy_uuid=dict(type="str", aliases=["ipsla_track_list_uuid"]),
        track_policy=dict(
            type="dict",
            aliases=["ipsla_track_list"],
            options=dict(
                name=dict(type="str"),
                template=dict(type="str"),
                template_id=dict(type="str"),
            ),
            required_by={
                "template": "name",
                "template_id": "name",
            },
            mutually_exclusive=[
                ["template", "template_id"],
            ],
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["prefix"]],
            ["state", "absent", ["prefix"]],
        ],
        required_one_of=[
            ["template", "template_id"],
            ["l3out", "l3out_uuid"],
        ],
        mutually_exclusive=[
            ["template", "template_id"],
            ["l3out", "l3out_uuid"],
            ["track_policy_uuid", "track_policy"],
        ],
    )

    mso = MSOModule(module)
    mso_templates = MSOTemplates(mso)

    template_name = mso.params.get("template")
    template_id = mso.params.get("template_id")
    l3out = mso.params.get("l3out")
    l3out_uuid = mso.params.get("l3out_uuid")
    pod_id = mso.params.get("pod_id")
    node_id = mso.params.get("node_id")
    prefix = mso.params.get("prefix")
    description = mso.params.get("description")
    administrative_distance = mso.params.get("administrative_distance")
    bfd_tracking = mso.params.get("bfd_tracking")
    next_hop_null = mso.params.get("next_hop_null")
    track_policy_uuid = mso.params.get("track_policy_uuid")
    track_policy = mso.params.get("track_policy")
    if track_policy is not None and check_if_all_elements_are_none(track_policy.values()):
        track_policy = {}
    if track_policy and not (track_policy.get("name") and (track_policy.get("template") or track_policy.get("template_id"))):
        mso.fail_json(msg="track_policy.name and one of the following are required: track_policy.template, track_policy.template_id")

    state = mso.params.get("state")

    mso_template = mso_templates.get_template("l3out", template_name, template_id)
    mso_template.validate_template("l3out")
    l3out_object = mso_template.get_l3out_object(l3out_uuid, l3out, True)
    node_object = mso_template.get_l3out_node(l3out_object.details, pod_id, node_id, True)

    if track_policy or track_policy_uuid:
        if track_policy_uuid:
            track_policy_match = mso_template.get_template_object_by_uuid("ipslaTrackList", track_policy_uuid, True)
        else:
            track_policy_mso_template = mso_templates.get_template(
                "tenant",
                track_policy.get("template"),
                track_policy.get("template_id"),
                fail_module=True,
            )
            track_policy_match = track_policy_mso_template.get_ipsla_track_list(
                uuid=track_policy_uuid,
                name=track_policy.get("name"),
                fail_module=True,
            )
            track_policy_uuid = track_policy_match.details.get("uuid")

    match = mso_template.get_l3out_node_static_route(node_object.details, prefix)
    if prefix and match:
        set_node_static_route_details(mso_template, match.details)
        mso.existing = mso.previous = copy.deepcopy(match.details)  # Query a specific object
    elif match:
        mso.existing = [set_node_static_route_details(mso_template, obj) for obj in match]

    l3out_node_static_route_path = "/l3outTemplate/l3outs/{0}/nodes/{1}/staticRoutes/{2}".format(
        l3out_object.index, node_object.index, match.index if match else "-"
    )

    ops = []

    if state == "present":
        mso_values = {
            "prefix": prefix,
            "description": description if description else None,
            "fallbackPref": administrative_distance,
            "enableBFDTracking": bfd_tracking,
            "trackPolicyRef": track_policy_uuid if track_policy_uuid else None,
            "nullNextHop": next_hop_null,
        }

        if match:
            remove_data = []
            unwanted = []
            if description == "" and match.details.get("description"):
                remove_data.append("description")
                unwanted.append("description")
            if track_policy == {} or track_policy_uuid == "":
                remove_data.extend(["trackPolicyRef"])
                unwanted.extend(["trackPolicyRef", "trackPolicyName", "trackPolicyTemplateName", "trackPolicyTemplateId"])
            append_update_ops_data(ops, match.details, l3out_node_static_route_path, mso_values, remove_data)
            mso.sanitize(mso_values, collate=True, unwanted=unwanted)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=l3out_node_static_route_path, value=mso.sent))

        set_node_static_route_details(mso_template, mso.proposed)

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=l3out_node_static_route_path))

    if not mso.module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        l3out_object = mso_template.get_l3out_object(l3out_uuid, l3out, True, search_object=response)
        node_object = mso_template.get_l3out_node(l3out_object.details, pod_id, node_id, True)
        match = mso_template.get_l3out_node_static_route(node_object.details, prefix)
        if match:
            set_node_static_route_details(mso_template, match.details)
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif mso.module.check_mode and state != "query":  # When the state is present/absent with check mode
        set_node_static_route_details(mso_template, mso.proposed)
        mso.existing = mso.proposed if state == "present" else {}
    mso.exit_json()


def set_node_static_route_details(mso_template, node_static_route):
    if node_static_route:
        reference_details = None
        if node_static_route.get("trackPolicyRef"):
            reference_details = {
                "track_list_reference": {
                    "name": "trackPolicyName",
                    "reference": "trackPolicyRef",
                    "type": "ipslaTrackList",
                    "template": "trackPolicyTemplateName",
                    "templateId": "trackPolicyTemplateId",
                }
            }
        mso_template.update_config_with_template_and_references(
            node_static_route,
            reference_details,
            True,
        )

    return node_static_route


if __name__ == "__main__":
    main()
