#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_tenant_igmp_interface_policy
short_description: Manage Internet Group Management Protocol (IGMP) Interface Policies in Tenant Policy Templates on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage IGMP Interface Policies in Tenant Policy Templates on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Anvitha Jain (@anvjain)
options:
  template:
    description:
    - The name of the tenant template.
    - This parameter or O(template_id) is required.
    type: str
    aliases: [ tenant_template ]
    required: true
  template_id:
    description:
    - The ID of the L3Out template.
    - This parameter or O(template) is required.
    type: str
    aliases: [ l3out_template_id ]
  name:
    description:
    - The name of the IGMP Interface Policy.
    type: str
    aliases: [ igmp_interface_policy ]
  uuid:
    description:
    - The UUID of the IGMP Interface Policy.
    - This parameter is required when the IGMP Interface Policy O(name) needs to be updated.
    type: str
    aliases: [ igmp_interface_policy_uuid ]
  description:
    description:
    - The description of the IGMP Interface Policy.
    - Providing an empty string will remove the O(description="") from the IGMP Interface Policy.
    type: str
  version3_asm:
    description:
    - Enable or disable IGMP version 3 ASM.
    - Defaults to C(disabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
    aliases: [ allow_version3_asm ]
  fast_leave:
    description:
    - Enable or disable fast leave.
    - Defaults to C(disabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
  report_link_local_groups:
    description:
    - Enable or disable reporting link-local groups.
    - Defaults to C(disabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
  igmp_version:
    description:
    - The IGMP version of the IGMP Interface Policy.
    - Defaults to C(v2) when unset during creation.
    type: str
    choices: [ v2, v3 ]
  group_timeout:
    description:
    - The group timeout value in seconds.
    - Defaults to 260 when unset during creation.
    - The valid range is from 3 to 65535.
    type: int
  query_interval:
    description:
    - The query interval value in seconds.
    - Defaults to 125 when unset during creation.
    - The valid range is from 1 to 18000.
    type: int
  query_response_interval:
    description:
    - The query response interval value in seconds.
    - Defaults to 10 when unset during creation.
    - The valid range is from 1 to 25.
    type: int
  last_member_count:
    description:
    - The last member query count value.
    - Defaults to 2 when unset during creation.
    - The valid range is from 1 to 5.
    type: int
  last_member_response_time:
    description:
    - The last member query response time value in seconds.
    - Defaults to 1 when unset during creation.
    - The valid range is from 1 to 25.
    type: int
  startup_query_count:
    description:
    - The startup query count value.
    - Defaults to 2 when unset during creation.
    - The valid range is from 1 to 10.
    type: int
  startup_query_interval:
    description:
    - The startup query interval value in seconds.
    - Defaults to 31 when unset during creation.
    - The valid range is from 1 to 18000.
    type: int
  querier_timeout:
    description:
    - The querier timeout value in seconds.
    - Defaults to 255 when unset during creation.
    - The valid range is from 1 to 65535.
    type: int
  robustness_variable:
    description:
    - The robustness variable value.
    - Defaults to 2 when unset during creation.
    - The valid range is from 1 to 7.
    type: int
  state_limit_route_map_uuid:
    description:
    - The UUID of the state limit route map.
    - Providing an empty string will remove the O(state_limit_route_map_uuid="") from IGMP Interface Policy.
    type: str
    aliases: [ state_limit_route_map_for_multicast ]
  state_limit_route_map:
    description:
    - The Route Map Policy for Multicast.
    - This parameter can be used instead of O(state_limit_route_map_uuid).
    - If both parameter are used, O(state_limit_route_map) will be ignored.
    - Providing an empty map will remove the O(state_limit_route_map={}) from IGMP Interface Policy.
    type: dict
    suboptions:
      name:
        description:
        - The name of the Route Map Policy for Multicast.
        type: str
    aliases: [ state_limit_route_map_policy, state_limit_route_map_policy_multicast ]
  report_policy_route_map_uuid:
    description:
    - The UUID of the report policy route map.
    - Providing an empty string will remove the O(report_policy_route_map_uuid="") from IGMP Interface Policy.
    type: str
    aliases: [ report_policy_route_map_for_multicast ]
  report_policy_route_map:
    description:
    - The Route Map Policy for Multicast.
    - This parameter can be used instead of O(report_policy_route_map_uuid).
    - If both parameter are used, O(report_policy_route_map) will be ignored.
    - Providing an empty map will remove the O(report_policy_route_map={}) from IGMP Interface Policy.
    type: dict
    suboptions:
      name:
        description:
        - The name of the Route Map Policy for Multicast.
        type: str
    aliases: [ report_policy_route_map_policy, report_policy_route_map_policy_multicast ]
  static_report_route_map_uuid:
    description:
    - The UUID of the static report route map.
    - Providing an empty string will remove the O(static_report_route_map_uuid="") from IGMP Interface Policy.
    type: str
    aliases: [ static_report_route_map_for_multicast ]
  static_report_route_map:
    description:
    - The Route Map Policy for Multicast.
    - This parameter can be used instead of O(static_report_route_map_uuid).
    - If both parameter are used, O(static_report_route_map) will be ignored.
    - Providing an empty map will remove the O(static_report_route_map={}) from IGMP Interface Policy.
    type: dict
    suboptions:
      name:
        description:
        - The name of the Route Map Policy for Multicast.
        type: str
    aliases: [ static_report_route_map_policy, static_report_route_map_policy_multicast ]
  maximum_multicast_entries:
    description:
    - The maximum multicast entries value.
    - Defaults to 4294967295 when unset during creation.
    - The valid range is from 1 to 4294967295.
    - This parameter is only applicable when the O(state_limit_route_map_uuid) or O(state_limit_route_map) is not empty.
    type: int
  reserved_multicast_entries:
    description:
    - The reserved multicast entries value.
    - Defaults to 0 when unset during creation.
    - The valid range is from 0 to 4294967295.
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
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Tenant template.
- The O(state_limit_route_map_uuid) or O(state_limit_route_map) requires Route Map Policy for Multicast.
  The O(report_policy_route_map_uuid) or O(report_policy_route_map) requires Route Map Policy for Multicast.
  The O(static_report_route_map_uuid) or O(static_report_route_map) requires Route Map Policy for Multicast.
  Use M(cisco.mso.ndo_route_map_policy_multicast) to create the Route Map Policy for Multicast.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_route_map_policy_multicast
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create an IGMP Interface Policy
  cisco.mso.ndo_tenant_igmp_interface_policy:
    template: ansible_tenant_template
    name: test_igmp_interface_policy
    description: Test Description
    version3_asm: enabled
    fast_leave: enabled
    report_link_local_groups: enabled
    igmp_version: v3
    group_timeout: 260
    query_interval: 125
    query_response_interval: 10
    last_member_count: 2
    last_member_response_time: 1
    startup_query_count: 2
    startup_query_interval: 31
    querier_timeout: 255
    robustness_variable: 2
    state_limit_route_map_uuid: "2be2b2e6-727d-4534-9d09-4abc36ed0194"
    report_policy_route_map_uuid: "{{ route_map_policy_for_multicast.current.uuid }}"
    static_report_route_map:
      name: TestStaticReportRouteMap
    maximum_multicast_entries: 4294967295
    reserved_multicast_entries: 4294967
    state: present
  register: igmp_interface_policy

- name: Update an IGMP Interface Policy name with the UUID
  cisco.mso.ndo_tenant_igmp_interface_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: test_igmp_interface_policy_updated
    uuid: "{{ igmp_interface_policy.current.uuid }}"
    state: present
  register: igmp_interface_policy_update

- name: Query an IGMP Interface Policy with the name
  cisco.mso.ndo_tenant_igmp_interface_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: test_igmp_interface_policy
    state: query
  register: query

- name: Query an IGMP Interface Policy with the UUID
  cisco.mso.ndo_tenant_igmp_interface_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ igmp_interface_policy.current.uuid }}"
    state: query
  register: query_uuid

- name: Query all IGMP Interface Policies in the template
  cisco.mso.ndo_tenant_igmp_interface_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Delete an IGMP Interface Policy with the name
  cisco.mso.ndo_tenant_igmp_interface_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: test_igmp_interface_policy
    state: absent

- name: Delete an IGMP Interface Policy with the UUID
  cisco.mso.ndo_tenant_igmp_interface_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ igmp_interface_policy.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP
from ansible_collections.cisco.mso.plugins.module_utils.utils import (
    append_update_ops_data,
    check_if_all_elements_are_none,
)


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True, aliases=["tenant_template"]),
        template_id=dict(type="str", aliases=["l3out_template_id"]),
        name=dict(type="str", aliases=["igmp_interface_policy"]),
        uuid=dict(type="str", aliases=["igmp_interface_policy_uuid"]),
        description=dict(type="str"),
        version3_asm=dict(type="str", aliases=["allow_version3_asm"], choices=["enabled", "disabled"]),
        fast_leave=dict(type="str", choices=["enabled", "disabled"]),
        report_link_local_groups=dict(type="str", choices=["enabled", "disabled"]),
        igmp_version=dict(type="str", choices=["v2", "v3"]),
        group_timeout=dict(type="int"),
        query_interval=dict(type="int"),
        query_response_interval=dict(type="int"),
        last_member_count=dict(type="int"),
        last_member_response_time=dict(type="int"),
        startup_query_count=dict(type="int"),
        startup_query_interval=dict(type="int"),
        querier_timeout=dict(type="int"),
        robustness_variable=dict(type="int"),
        state_limit_route_map_uuid=dict(type="str", aliases=["state_limit_route_map_for_multicast"]),
        state_limit_route_map=dict(
            type="dict",
            options=dict(
                name=dict(type="str"),
            ),
            aliases=["state_limit_route_map_policy", "state_limit_route_map_policy_multicast"],
        ),
        report_policy_route_map_uuid=dict(type="str", aliases=["report_policy_route_map_for_multicast"]),
        report_policy_route_map=dict(
            type="dict",
            options=dict(
                name=dict(type="str"),
            ),
            aliases=["report_policy_route_map_policy", "report_policy_route_map_policy_multicast"],
        ),
        static_report_route_map_uuid=dict(type="str", aliases=["static_report_route_map_for_multicast"]),
        static_report_route_map=dict(
            type="dict",
            options=dict(
                name=dict(type="str"),
            ),
            aliases=["static_report_route_map_policy", "static_report_route_map_policy_multicast"],
        ),
        maximum_multicast_entries=dict(type="int"),
        reserved_multicast_entries=dict(type="int"),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
        mutually_exclusive=[
            ["template", "template_id"],
            ["state_limit_route_map_uuid", "state_limit_route_map"],
            ["report_policy_route_map_uuid", "report_policy_route_map"],
            ["static_report_route_map_uuid", "static_report_route_map"],
        ],
        required_one_of=[
            ["template", "template_id"],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    template_id = module.params.get("template_id")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    version3_asm = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(module.params.get("version3_asm"))
    fast_leave = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(module.params.get("fast_leave"))
    report_link_local_groups = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(module.params.get("report_link_local_groups"))
    igmp_version = module.params.get("igmp_version")
    group_timeout = module.params.get("group_timeout")
    query_interval = module.params.get("query_interval")
    query_response_interval = module.params.get("query_response_interval")
    last_member_count = module.params.get("last_member_count")
    last_member_response_time = module.params.get("last_member_response_time")
    startup_query_count = module.params.get("startup_query_count")
    startup_query_interval = module.params.get("startup_query_interval")
    querier_timeout = module.params.get("querier_timeout")
    robustness_variable = module.params.get("robustness_variable")
    state_limit_route_map_uuid = module.params.get("state_limit_route_map_uuid")
    state_limit_route_map = module.params.get("state_limit_route_map")
    report_policy_route_map_uuid = module.params.get("report_policy_route_map_uuid")
    report_policy_route_map = module.params.get("report_policy_route_map")
    static_report_route_map_uuid = module.params.get("static_report_route_map_uuid")
    static_report_route_map = module.params.get("static_report_route_map")
    maximum_multicast_entries = module.params.get("maximum_multicast_entries")
    reserved_multicast_entries = module.params.get("reserved_multicast_entries")
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "tenant", template, template_id)
    mso_template.validate_template("tenantPolicy")
    ops = []
    empty_state_limit_route_map = False
    empty_report_policy_route_map = False
    empty_static_report_route_map = False

    existing_igmp_interface_policies = mso_template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("igmpInterfacePolicies", [])
    object_description = "IGMP Interface Policy"
    path = "/tenantPolicyTemplate/template/igmpInterfacePolicies"

    reference_dict = {
        "stateLimitRouteMap": {"name": "stateLimitRouteMapName", "reference": "stateLimitRouteMapRef", "type": "mcastRouteMap"},
        "reportPolicyRouteMap": {"name": "reportPolicyRouteMapName", "reference": "reportPolicyRouteMapRef", "type": "mcastRouteMap"},
        "staticReportRouteMap": {"name": "staticReportRouteMapName", "reference": "staticReportRouteMapRef", "type": "mcastRouteMap"},
    }

    if uuid or name:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_igmp_interface_policies,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            mso_template.update_config_with_template_and_references(match.details, reference_dict)
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = [
            mso_template.update_config_with_template_and_references(igmp_interface_policy, reference_dict)
            for igmp_interface_policy in existing_igmp_interface_policies
        ]

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        mso_values = dict(
            name=name,
            description=description,
            enableV3Asm=version3_asm,
            enableFastLeaveControl=fast_leave,
            enableReportLinkLocalGroups=report_link_local_groups,
            igmpQuerierVersion=igmp_version,
            groupTimeout=group_timeout,
            queryInterval=query_interval,
            queryResponseInterval=query_response_interval,
            lastMemberCount=last_member_count,
            lastMemberResponseInterval=last_member_response_time,
            startQueryCount=startup_query_count,
            startQueryInterval=startup_query_interval,
            querierTimeout=querier_timeout,
            robustnessFactor=robustness_variable,
            maximumMulticastEntries=maximum_multicast_entries,
            reservedMulticastEntries=reserved_multicast_entries,
            stateLimitRouteMapRef=state_limit_route_map_uuid,
            reportPolicyRouteMapRef=report_policy_route_map_uuid,
            staticReportRouteMapRef=static_report_route_map_uuid,
        )

        if state_limit_route_map:
            empty_state_limit_route_map = check_if_all_elements_are_none(list(state_limit_route_map.values()))
            if not empty_state_limit_route_map:
                mso_values["stateLimitRouteMapRef"] = mso_template.get_route_map_policy_for_multicast_uuid(state_limit_route_map.get("name"))

        if report_policy_route_map:
            empty_report_policy_route_map = check_if_all_elements_are_none(list(report_policy_route_map.values()))
            if not empty_report_policy_route_map:
                mso_values["reportPolicyRouteMapRef"] = mso_template.get_route_map_policy_for_multicast_uuid(report_policy_route_map.get("name"))

        if static_report_route_map:
            empty_static_report_route_map = check_if_all_elements_are_none(list(static_report_route_map.values()))
            if not empty_static_report_route_map:
                mso_values["staticReportRouteMapRef"] = mso_template.get_route_map_policy_for_multicast_uuid(static_report_route_map.get("name"))

        if match:
            mso_values_remove = list()

            if (state_limit_route_map_uuid == "" or empty_state_limit_route_map) and match.details.get("stateLimitRouteMapRef"):
                mso_values_remove.append("stateLimitRouteMapRef")
            if (report_policy_route_map_uuid == "" or empty_report_policy_route_map) and match.details.get("reportPolicyRouteMapRef"):
                mso_values_remove.append("reportPolicyRouteMapRef")
            if (static_report_route_map_uuid == "" or empty_static_report_route_map) and match.details.get("staticReportRouteMapRef"):
                mso_values_remove.append("staticReportRouteMapRef")

            append_update_ops_data(ops, match.details, "{0}/{1}".format(path, match.index), mso_values, mso_values_remove)
            mso.sanitize(match.details, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="{0}/-".format(path), value=mso.sent))

    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))

    if not module.check_mode and ops:
        response_object = mso.request(mso_template.template_path, method="PATCH", data=ops)
        existing_igmp_interface_policies = response_object.get("tenantPolicyTemplate", {}).get("template", {}).get("igmpInterfacePolicies", [])
        match = mso_template.get_object_by_key_value_pairs(
            object_description, existing_igmp_interface_policies, [KVPair("uuid", uuid) if uuid else KVPair("name", name)]
        )
        if match:
            mso_template.update_config_with_template_and_references(match.details, reference_dict)
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso_template.update_config_with_template_and_references(mso.proposed, reference_dict)
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
