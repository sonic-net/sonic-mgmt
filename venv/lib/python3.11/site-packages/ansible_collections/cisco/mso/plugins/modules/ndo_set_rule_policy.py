#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Samita Bhattacharjee (@samiib) <samitab@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: ndo_set_rule_policy
version_added: "2.12.0"
short_description: Manage Tenant Set Rule Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Tenant Set Rule Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v4.1 (NDO v5.1) and later.
author:
- Samita Bhattacharjee (@samiib)
options:
  template:
    description:
    - The name of the template.
    - The template must be a tenant template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the tenant template.
    - This parameter or O(template) is required.
    type: str
  name:
    description:
    - The name of the Set Rule Policy.
    type: str
    aliases: [ set_rule_policy ]
  uuid:
    description:
    - The UUID of the Set Rule Policy.
    - This parameter is required when the O(name) attribute needs to be updated.
    type: str
    aliases: [ set_rule_policy_uuid ]
  description:
    description:
    - The description of the Set Rule Policy.
    type: str
  set_community:
    description:
    - The community rule to add to the Set Rule Policy.
    - Providing an empty dictionary will remove the O(set_community={}) rule from the Set Rule Policy.
    type: dict
    suboptions:
      community:
        description:
        - The community value.
        type: str
      criteria:
        description:
        - The criteria to be applied to the community value.
        type: str
        choices: [ none, replace, append ]
  set_route_tag:
    description:
    - The route tag rule to add to the Set Rule Policy.
    - The value must be a number between 0 and 999999999.
    - Providing an empty string will remove the O(set_route_tag="") rule from the Set Rule Policy.
    type: str
  set_dampening:
    description:
    - The dampening rule to add to the Set Rule Policy.
    - Providing an empty dictionary will remove the O(set_dampening={}) rule from the Set Rule Policy.
    type: dict
    suboptions:
      half_life:
        description:
        - The half life time in minutes.
        - The value must be between 1 and 60.
        type: int
      reuse_limit:
        description:
        - The re-use limit.
        - The value must be between 1 and 20000.
        type: int
      suppress_limit:
        description:
        - The suppress limit.
        - The value must be between 1 and 20000.
        type: int
      max_suppress_time:
        description:
        - The maximum suppress time in minutes.
        - The value must be between 1 and 255.
        type: int
  set_weight:
    description:
    - The weight rule to add to the Set Rule Policy.
    - The value must be a number between 0 and 9999.
    - Providing an empty string will remove the O(set_weight="") rule from the Set Rule Policy.
    type: str
  set_next_hop:
    description:
    - The next hop rule to add to the Set Rule Policy.
    - The value must be a valid IPv4 or IPv6 address.
    - Providing an empty string will remove the O(set_next_hop="") rule from the Set Rule Policy.
    type: str
  set_preference:
    description:
    - The preference rule to add to the Set Rule Policy.
    - The value must be between 0 and 999999999.
    - Providing an empty string will remove the O(set_preference="") rule from the Set Rule Policy.
    type: str
  set_metric:
    description:
    - The metric rule to add to the Set Rule Policy.
    - The value must be between 0 and 999999999.
    - Providing an empty string will remove the O(set_metric="") rule from the Set Rule Policy.
    type: str
  set_metric_type:
    description:
    - The type of metric rule to add to the Set Rule Policy.
    - Providing an empty string will remove the O(set_metric_type="") from the Set Rule Policy.
    type: str
    choices: [ ospf_type1, ospf_type2, type1, type2, '' ]
  set_next_hop_propagate:
    description:
    - The next hop propagation value to add to the Set Rule Policy.
    - Providing a value of C(false) will remove next hop propagation from the Set Rule Policy.
    - O(set_next_hop_propagate) cannot be enabled with O(set_route_tag) configured.
    type: bool
  set_multi_path:
    description:
    - The multipath option to add to the Set Rule Policy.
    - Providing a value of C(false) will remove multipath from the Set Rule Policy.
    - Enabling multipath requires O(set_next_hop_propagate=true) to be enabled.
    type: bool
  set_additional_community:
    description:
    - The append list of communities to configure in the Set Rule Policy.
    - Providing an empty list will remove the O(set_additional_community=[]) from the Set Rule Policy.
    type: list
    elements: str
    aliases: [ set_add_communities ]
  set_as_path:
    description:
    - The Autonomous System (AS) path rules to add to the Set Rule Policy.
    - Providing an empty dictionary will remove the O(set_as_path={}) rules from the Set Rule Policy.
    type: dict
    suboptions:
      last_asn_count:
        description:
        - The prepend last AS count.
        - The value must be between 1 and 10.
        type: int
      path_asn_list:
        description:
        - The list of path AS numbers to prepend.
        - Providing an empty list will remove the O(set_as_path.path_asn_list=[]).
        type: list
        elements: dict
        suboptions:
          asn:
            description:
            - The AS number.
            - The value must be between 1 and 10.
            type: int
            required: true
          order:
            description:
            - The order of the AS number.
            - The value must be between 0 and 31.
            type: int
            required: true
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
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Tenant template.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new Set Rule Policy
  cisco.mso.ndo_set_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    name: set_rule_policy_1
    description: Ansible Set Rule Policy
    set_community:
      community: no-export
      criteria: replace
    set_additional_community:
      - no-advertise
      - extended:color:35
    set_route_tag: 500
    set_dampening:
      half_life: 15
      reuse_limit: 750
      suppress_limit: 2000
      max_suppress_time: 60
    set_weight: 50
    set_next_hop: 'aa::'
    set_preference: 200
    set_metric: 100
    set_metric_type: type2
    set_as_path:
      last_asn_count: 10
      path_asn_list:
        - order: 11
          asn: 1
        - order: 10
          asn: 2
    state: present
  register: create_set_rule_policy_1

- name: Update the name of the Set Rule Policy using UUID
  cisco.mso.ndo_set_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: "{{ create_tenant.current.templateId }}"
    uuid: "{{ create_set_rule_policy_1.current.uuid }}"
    name: set_rule_policy_1_updated
    state: present
  register: update_set_rule_policy_1

- name: Query an existing Set Rule Policy using UUID
  cisco.mso.ndo_set_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    uuid: "{{ create_set_rule_policy_1.current.uuid }}"
    state: query
  register: query_with_uuid

- name: Query an existing Set Rule Policy using name
  cisco.mso.ndo_set_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    name: set_rule_policy_1_updated
    state: query
  register: query_with_name

- name: Query all Set Rule Policies
  cisco.mso.ndo_set_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    state: query
  register: query_all

- name: Remove set rules from a Set Rule Policy
  cisco.mso.ndo_set_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    name: set_rule_policy_1_updated
    set_additional_community: []
    set_community: {}
    set_route_tag: ''
    set_propagate_next_hop: false
    state: present

- name: Delete an existing Set Rule Policy using UUID
  cisco.mso.ndo_set_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    uuid: "{{ create_set_rule_policy_1.current.uuid }}"
    state: absent

- name: Delete an existing Set Rule Policy using Name
  cisco.mso.ndo_set_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    name: set_rule_policy_1_updated
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data, check_if_all_elements_are_none
from ansible_collections.cisco.mso.plugins.module_utils.constants import ROUTE_MAP_METRIC_TYPE_MAP
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        name=dict(type="str", aliases=["set_rule_policy"]),
        uuid=dict(type="str", aliases=["set_rule_policy_uuid"]),
        description=dict(type="str"),
        set_community=dict(
            type="dict",
            options=dict(
                community=dict(type="str"),
                criteria=dict(type="str", choices=["none", "replace", "append"]),
            ),
        ),
        set_route_tag=dict(type="str"),
        set_weight=dict(type="str"),
        set_dampening=dict(
            type="dict",
            options=dict(
                half_life=dict(type="int"),
                reuse_limit=dict(type="int"),
                suppress_limit=dict(type="int"),
                max_suppress_time=dict(type="int"),
            ),
        ),
        set_next_hop=dict(type="str"),
        set_preference=dict(type="str"),
        set_metric=dict(type="str"),
        set_metric_type=dict(type="str", choices=list(ROUTE_MAP_METRIC_TYPE_MAP)),
        set_next_hop_propagate=dict(type="bool"),
        set_multi_path=dict(type="bool"),
        set_additional_community=dict(type="list", elements="str", aliases=["set_add_communities"]),
        set_as_path=dict(
            type="dict",
            options=dict(
                last_asn_count=dict(type="int"),
                path_asn_list=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        asn=dict(type="int", required=True),
                        order=dict(type="int", required=True),
                    ),
                ),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("template", "template_id"),
        ],
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
        required_one_of=[["template", "template_id"]],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    template_id = module.params.get("template_id")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    set_community = module.params.get("set_community")
    set_route_tag = get_int_empty_or_none(module.params.get("set_route_tag"))
    set_weight = get_int_empty_or_none(module.params.get("set_weight"))
    set_preference = get_int_empty_or_none(module.params.get("set_preference"))
    set_metric = get_int_empty_or_none(module.params.get("set_metric"))
    set_dampening = module.params.get("set_dampening")
    set_next_hop = module.params.get("set_next_hop")
    set_metric_type = ROUTE_MAP_METRIC_TYPE_MAP.get(module.params.get("set_metric_type"), None)
    set_next_hop_propagate = module.params.get("set_next_hop_propagate")
    set_multi_path = module.params.get("set_multi_path")
    set_additional_community = module.params.get("set_additional_community")
    if set_additional_community is not None and len(set_additional_community) > 0:
        set_additional_community = [dict(criteria="append", community=comm) for comm in set_additional_community]
    set_as_path = None
    if module.params.get("set_as_path") is not None:
        set_as_path = []
        last_asn_count = module.params.get("set_as_path", {}).get("last_asn_count")
        path_asn_list = module.params.get("set_as_path", {}).get("path_asn_list")
        if last_asn_count is not None:
            set_as_path.append(dict(criteria="prepend-last-as", asnCount=last_asn_count))
        if path_asn_list is not None:
            set_as_path.append(dict(criteria="prepend", pathASNs=path_asn_list))
    state = module.params.get("state")

    if set_dampening is not None and check_if_all_elements_are_none(set_dampening.values()):
        set_dampening = {}

    if set_community is not None and check_if_all_elements_are_none(set_community.values()):
        set_community = {}

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "tenant", template, template_id)
    mso_template.validate_template("tenantPolicy")

    object_description = "Set Rule Policy"
    path = "/tenantPolicyTemplate/template/setRulePolicies"
    set_rule_policy_path = None

    match = mso_template.get_set_rule_policy_object(uuid, name, search_object=None, fail_module=False)
    if (name or uuid) and match:
        set_rule_policy_path = "{0}/{1}".format(path, match.index)
        mso_template.update_config_with_template_and_references(match.details)
        mso.existing = copy.deepcopy(match.details)
        mso.previous = copy.deepcopy(match.details)
    elif match:
        mso.existing = mso.previous = [mso_template.update_config_with_template_and_references(obj) for obj in match]

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        if match:
            mso_values = dict(name=name, description=description)
            mso_values_remove = list()

            if set_route_tag == "" and match.details.get("setRouteTag"):
                mso_values_remove.append("setRouteTag")
            elif set_route_tag:
                mso_values["setRouteTag"] = set_route_tag

            if set_weight == "" and match.details.get("setWeight"):
                mso_values_remove.append("setWeight")
            elif set_weight:
                mso_values["setWeight"] = set_weight

            if set_next_hop == "" and match.details.get("setNextHop"):
                mso_values_remove.append("setNextHop")
            elif set_next_hop:
                mso_values["setNextHop"] = set_next_hop

            if set_preference == "" and match.details.get("setPreference"):
                mso_values_remove.append("setPreference")
            elif set_preference:
                mso_values["setPreference"] = set_preference

            if set_metric == "" and match.details.get("setMetric"):
                mso_values_remove.append("setMetric")
            elif set_metric:
                mso_values["setMetric"] = set_metric

            if set_metric_type == "" and match.details.get("setMetricType"):
                mso_values_remove.append("setMetricType")
            elif set_metric_type:
                mso_values["setMetricType"] = set_metric_type

            if set_next_hop_propagate is False and match.details.get("setNextHopPropagate"):
                mso_values_remove.append("setNextHopPropagate")
            elif set_next_hop_propagate:
                mso_values["setNextHopPropagate"] = set_next_hop_propagate

            if set_multi_path is False and match.details.get("setMultiPath"):
                mso_values_remove.append("setMultiPath")
            elif set_multi_path:
                mso_values["setMultiPath"] = set_multi_path

            if set_additional_community == [] and match.details.get("setAddCommunities"):
                mso_values_remove.append("setAddCommunities")
            elif set_additional_community:
                mso_values["setAddCommunities"] = set_additional_community

            if set_as_path == [] and match.details.get("setAsPath"):
                mso_values_remove.append("setAsPath")
            elif set_as_path:
                mso_values["setAsPath"] = set_as_path

            if set_community == {} and match.details.get("setCommunity"):
                mso_values_remove.append("setCommunity")
            elif set_community:
                mso_values[("setCommunity", "community")] = set_community.get("community")
                mso_values[("setCommunity", "criteria")] = set_community.get("criteria")

            if set_dampening == {} and match.details.get("setDampening"):
                mso_values_remove.append("setDampening")
            elif set_dampening:
                mso_values[("setDampening", "halfLife")] = set_dampening.get("half_life")
                mso_values[("setDampening", "reuseLimit")] = set_dampening.get("reuse_limit")
                mso_values[("setDampening", "suppressLimit")] = set_dampening.get("suppress_limit")
                mso_values[("setDampening", "maxSuppressTime")] = set_dampening.get("max_suppress_time")
            proposed_payload = copy.deepcopy(match.details)
            append_update_ops_data(ops, proposed_payload, set_rule_policy_path, mso_values, mso_values_remove)
            mso.sanitize(proposed_payload, collate=True)
        else:
            mso_values = dict(
                name=name,
                description=description,
                setRouteTag=set_route_tag,
                setWeight=set_weight,
                setNextHop=set_next_hop,
                setPreference=set_preference,
                setMetric=set_metric,
                setMetricType=set_metric_type,
                setNextHopPropagate=set_next_hop_propagate,
                setMultiPath=set_multi_path,
                setAddCommunities=set_additional_community,
                setAsPath=set_as_path,
                setCommunity=set_community,
                setDampening=(
                    dict(
                        halfLife=set_dampening.get("half_life"),
                        reuseLimit=set_dampening.get("reuse_limit"),
                        suppressLimit=set_dampening.get("suppress_limit"),
                        maxSuppressTime=set_dampening.get("max_suppress_time"),
                    )
                    if set_dampening
                    else None
                ),
            )
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="{0}/-".format(path), value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=set_rule_policy_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = mso_template.get_set_rule_policy_object(uuid, name, search_object=response, fail_module=False)
        if match:
            mso_template.update_config_with_template_and_references(match.details)
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso_template.update_config_with_template_and_references(mso.proposed)
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def get_int_empty_or_none(value):
    if value == "":
        return ""
    return int(value) if value is not None else None


if __name__ == "__main__":
    main()
