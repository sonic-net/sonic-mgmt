#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_node_static_route_next_hop
version_added: "2.11.0"
short_description: Manage L3Out Node Static Route Next Hops on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Out Node Static Route Next Hops on Cisco Nexus Dashboard Orchestrator (NDO).
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
    required: true
  ip:
    description:
    - The IP address of the static route next hop.
    type: str
    aliases: [ ip_address, next_hop ]
  description:
    description:
    - The description of the static route next hop.
    - Providing an empty string O(description="") will remove the description from the static route next hop.
    type: str
  administrative_distance:
    description:
    - The administrative distance of the static route.
    - The value must be in the range 0 - 255.
    - Defaults to O(administrative_distance=0) when unset during creation.
    type: int
    aliases: [ admin_distance ]
  monitoring_policy_uuid:
    description:
    - The UUID of the Monitoring Policy to be used.
    - Providing an empty string O(monitoring_policy="") will remove the Monitoring Policy from the static route next hop.
    type: str
    aliases: [ ipsla_monitoring_policy_uuid ]
  monitoring_policy:
    description:
    - The Monitoring Policy to be used.
    - Providing an empty dictionary O(monitoring_policy={}) will remove the Monitoring Policy from the static route next hop.
    type: dict
    aliases: [ ipsla_monitoring_policy ]
    suboptions:
      name:
        description:
        - The name of the monitoring policy.
        type: str
      template:
        description:
        - The name of the template that contains the monitoring policy.
        - This parameter or O(monitoring_policy.template_id) is required.
        type: str
      template_id:
        description:
        - The ID of the template that contains the monitoring policy.
        - This parameter or O(monitoring_policy.template) is required.
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
- The O(monitoring_policy) or O(monitoring_policy_uuid) must exist before using this module in your playbook.
  The M(cisco.mso.ndo_ipsla_monitoring_policy) module can be used for this.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_l3out_template
- module: cisco.mso.ndo_ipsla_monitoring_policy
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a L3Out Node Static Route Next Hop
  cisco.mso.ndo_l3out_node_static_route_next_hop:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    pod_id: 1
    node_id: 101
    prefix: 10.0.0.0/24
    ip: 11.0.0.1
    state: present

- name: Update an existing L3Out Node Static Route Next Hop
  cisco.mso.ndo_l3out_node_static_route_next_hop:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: "{{ l3out_template.current.templateId }}"
    l3out_uuid: "{{ l3out.current.uuid }}"
    pod_id: 1
    node_id: 101
    prefix: 10.0.0.0/24
    ip: 11.0.0.1
    description: "Updated static route next hop"
    administrative_distance: 10
    monitoring_policy:
      name: "monitoring_policy_name"
      template: "monitoring_policy_template"
    state: present

- name: Query an existing L3Out Node Static Route Next Hop
  cisco.mso.ndo_l3out_node_static_route_next_hop:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    pod_id: 1
    node_id: 101
    prefix: 10.0.0.0/24
    ip: 10.0.0.1
    state: query
  register: query_with_name

- name: Query all existing L3Out Node Static Route Next Hops in a L3Out Node
  cisco.mso.ndo_l3out_node_static_route_next_hop:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    pod_id: 1
    node_id: 101
    prefix: 10.0.0.0/24
    state: query

- name: Delete an existing L3Out Node Static Route Next Hop
  cisco.mso.ndo_l3out_node_static_route_next_hop:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    pod_id: 1
    node_id: 101
    prefix: 10.0.0.0/24
    ip: 10.0.0.1
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
        prefix=dict(type="str", required=True),
        ip=dict(type="str", aliases=["ip_address", "next_hop"]),
        description=dict(type="str"),
        administrative_distance=dict(type="int", aliases=["admin_distance"]),
        monitoring_policy_uuid=dict(type="str", aliases=["ipsla_monitoring_policy_uuid"]),
        monitoring_policy=dict(
            type="dict",
            aliases=["ipsla_monitoring_policy"],
            options=dict(
                name=dict(type="str"),
                template=dict(type="str"),
                template_id=dict(type="str"),
            ),
            required_by={
                "template": "name",
                "template_id": "name",
            },
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
            ["monitoring_policy_uuid", "monitoring_policy"],
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
    ip = mso.params.get("ip")
    description = mso.params.get("description")
    administrative_distance = mso.params.get("administrative_distance")
    monitoring_policy_uuid = mso.params.get("monitoring_policy_uuid")
    monitoring_policy = mso.params.get("monitoring_policy")
    if monitoring_policy is not None and check_if_all_elements_are_none(monitoring_policy.values()):
        monitoring_policy = {}
    if monitoring_policy and not (monitoring_policy.get("name") and (monitoring_policy.get("template") or monitoring_policy.get("template_id"))):
        mso.fail_json(msg="monitoring_policy.name and one of the following are required: monitoring_policy.template, monitoring_policy.template_id")

    state = mso.params.get("state")

    mso_template = mso_templates.get_template("l3out", template_name, template_id)
    mso_template.validate_template("l3out")
    l3out_object = mso_template.get_l3out_object(l3out_uuid, l3out, True)
    node_object = mso_template.get_l3out_node(l3out_object.details, pod_id, node_id, True)
    static_route_object = mso_template.get_l3out_node_static_route(node_object.details, prefix, True)

    if monitoring_policy or monitoring_policy_uuid:
        if monitoring_policy_uuid:
            monitoring_policy_match = mso_template.get_template_object_by_uuid("ipslaMonitoringPolicy", monitoring_policy_uuid, True)
        else:
            monitoring_policy_mso_template = mso_templates.get_template(
                "tenant",
                monitoring_policy.get("template"),
                monitoring_policy.get("template_id"),
                fail_module=True,
            )
            monitoring_policy_match = monitoring_policy_mso_template.get_ipsla_monitoring_policy(
                uuid=monitoring_policy_uuid,
                name=monitoring_policy.get("name"),
                fail_module=True,
            )
            monitoring_policy_uuid = monitoring_policy_match.details.get("uuid")

    match = mso_template.get_l3out_node_static_route_next_hop(static_route_object.details, ip)
    if ip and match:
        set_node_static_route_next_hop_details(mso_template, match.details)
        mso.existing = mso.previous = copy.deepcopy(match.details)  # Query a specific object
    elif match:
        mso.existing = [set_node_static_route_next_hop_details(mso_template, obj) for obj in match]

    l3out_node_static_route_next_hop_path = "/l3outTemplate/l3outs/{0}/nodes/{1}/staticRoutes/{2}/nextHops/{3}".format(
        l3out_object.index, node_object.index, static_route_object.index, match.index if match else "-"
    )

    ops = []

    if state == "present":
        mso_values = {
            "nextHopIP": ip,
            "description": description if description else None,
            "preference": administrative_distance,
            "monitoringPolicyRef": monitoring_policy_uuid if monitoring_policy_uuid else None,
        }

        if match:
            remove_data = []
            unwanted = []
            if description == "" and match.details.get("description"):
                remove_data.append("description")
                unwanted.append("description")
            if monitoring_policy == {} or monitoring_policy_uuid == "":
                remove_data.extend(["monitoringPolicyRef"])
                unwanted.extend(["monitoringPolicyRef", "monitoringPolicyName", "monitoringPolicyTemplateName", "monitoringPolicyTemplateId"])
            append_update_ops_data(ops, match.details, l3out_node_static_route_next_hop_path, mso_values, remove_data)
            mso.sanitize(mso_values, collate=True, unwanted=unwanted)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=l3out_node_static_route_next_hop_path, value=mso.sent))

        set_node_static_route_next_hop_details(mso_template, mso.proposed)

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=l3out_node_static_route_next_hop_path))

    if not mso.module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        l3out_object = mso_template.get_l3out_object(l3out_uuid, l3out, True, search_object=response)
        node_object = mso_template.get_l3out_node(l3out_object.details, pod_id, node_id, True)
        static_route_object = mso_template.get_l3out_node_static_route(node_object.details, prefix, True)
        match = mso_template.get_l3out_node_static_route_next_hop(static_route_object.details, ip)
        if match:
            set_node_static_route_next_hop_details(mso_template, match.details)
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif mso.module.check_mode and state != "query":  # When the state is present/absent with check mode
        set_node_static_route_next_hop_details(mso_template, mso.proposed)
        mso.existing = mso.proposed if state == "present" else {}
    mso.exit_json()


def set_node_static_route_next_hop_details(mso_template, next_hop):
    if next_hop:
        reference_details = None
        if next_hop.get("monitoringPolicyRef"):
            reference_details = {
                "monitoring_list_reference": {
                    "name": "monitoringPolicyName",
                    "reference": "monitoringPolicyRef",
                    "type": "ipslaMonitoringPolicy",
                    "template": "monitoringPolicyTemplateName",
                    "templateId": "monitoringPolicyTemplateId",
                }
            }
        mso_template.update_config_with_template_and_references(
            next_hop,
            reference_details,
            True,
        )

    return next_hop


if __name__ == "__main__":
    main()
