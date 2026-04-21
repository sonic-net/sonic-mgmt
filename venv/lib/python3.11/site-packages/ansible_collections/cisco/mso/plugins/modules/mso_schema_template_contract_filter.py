#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_contract_filter
short_description: Manage contract filters in schema templates
description:
- Manage contract filters in schema templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template.
    type: str
    required: true
  contract:
    description:
    - The name of the contract to manage.
    type: str
    required: true
  description:
    description:
    - The description of contract is supported on versions of MSO/NDO that are 3.3 or greater.
    type: str
  contract_display_name:
    description:
    - The name as displayed on the MSO web interface.
    - This defaults to the contract name when unset on creation.
    type: str
  contract_filter_type:
    description:
    - DEPRECATION WARNING, contract_filter_type will not be used anymore and is deduced from filter_type.
    - The type of filters defined in this contract.
    - This defaults to C(both-way) when unset on creation.
    default: both-way
    type: str
    choices: [ both-way, one-way ]
  contract_scope:
    description:
    - The scope of the contract.
    - This defaults to C(vrf) when unset on creation.
    type: str
    choices: [ application-profile, global, tenant, vrf ]
  filter:
    description:
    - The filter to associate with this contract.
    type: str
    aliases: [ name ]
  filter_template:
    description:
    - The template name in which the filter is located.
    type: str
  filter_schema:
    description:
    - The schema name in which the filter is located.
    type: str
  filter_type:
    description:
    - The type of filter to manage.
    - Prior to MSO/NDO 3.3 remove and re-apply contract to change the filter type.
    type: str
    choices: [ both-way, consumer-to-provider, provider-to-consumer ]
    default: both-way
    aliases: [ type ]
  filter_directives:
    description:
    - A list of filter directives.
    type: list
    elements: str
    choices: [ log, none, policy_compression ]
  qos_level:
    description:
    - The Contract QoS Level parameter is supported on versions of MSO/NDO that are 3.3 or greater.
    type: str
    choices: [ unspecified, level1, level2, level3, level4, level5, level6 ]
  action:
    description:
    - The filter action parameter is supported on versions of MSO/NDO that are 3.3 or greater.
    type: str
    choices: [ permit, deny ]
  priority:
    description:
    - The filter priority override parameter is supported on versions of MSO/NDO that are 3.3 or greater.
    type: str
    choices: [ default, lowest_priority, medium_priority, highest_priority ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_filter_entry
notes:
- Due to restrictions of the MSO/NDO REST API this module creates contracts when needed, and removes them when the last filter has been removed.
- Due to restrictions of the MSO/NDO REST API concurrent modifications to contract filters can be dangerous and corrupt data.
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new contract filter
  cisco.mso.mso_schema_template_contract_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    contract: Contract 1
    contract_scope: global
    filter: Filter 1
    state: present

- name: Remove a contract filter
  cisco.mso.mso_schema_template_contract_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    contract: Contract 1
    filter: Filter 1
    state: absent

- name: Query a specific contract filter
  cisco.mso.mso_schema_template_contract_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    contract: Contract 1
    filter: Filter 1
    state: query
  register: query_result

- name: Query all contract filters
  cisco.mso.mso_schema_template_contract_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    contract: Contract 1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.constants import FILTER_KEY_MAP, PRIORITY_MAP, QOS_LEVEL


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        contract=dict(type="str", required=True),
        description=dict(type="str"),
        contract_display_name=dict(type="str"),
        contract_scope=dict(type="str", choices=["application-profile", "global", "tenant", "vrf"]),
        # Deprecated input: contract_filter_type is deduced from filter_type
        contract_filter_type=dict(type="str", default="both-way", choices=["both-way", "one-way"]),
        filter=dict(type="str", aliases=["name"]),  # This parameter is not required for querying all objects
        filter_directives=dict(type="list", elements="str", choices=["log", "none", "policy_compression"]),
        filter_template=dict(type="str"),
        filter_schema=dict(type="str"),
        filter_type=dict(type="str", default="both-way", choices=list(FILTER_KEY_MAP), aliases=["type"]),
        qos_level=dict(type="str", choices=QOS_LEVEL),
        action=dict(type="str", choices=["permit", "deny"]),
        priority=dict(type="str", choices=["default", "lowest_priority", "medium_priority", "highest_priority"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["filter"]],
            ["state", "present", ["filter"]],
        ],
    )

    schema = module.params.get("schema")
    template_name = module.params.get("template").replace(" ", "")
    contract_name = module.params.get("contract")
    contract_display_name = module.params.get("contract_display_name")
    description = module.params.get("description")
    # Deprecated input: contract_filter_type is deduced from filter_type.
    # contract_filter_type = module.params.get('contract_filter_type')
    contract_scope = module.params.get("contract_scope")
    filter_name = module.params.get("filter")
    filter_directives = module.params.get("filter_directives")
    filter_template = module.params.get("filter_template")
    filter_schema = module.params.get("filter_schema")
    filter_type = module.params.get("filter_type")
    filter_action = module.params.get("action")
    filter_priority = module.params.get("priority")
    qos_level = module.params.get("qos_level")

    state = module.params.get("state")

    mso = MSOModule(module)

    # Initialize variables
    ops = []
    filter_obj = None
    filter_key = FILTER_KEY_MAP.get(filter_type)
    filter_template = template_name if filter_template is None else filter_template.replace(" ", "")
    filter_schema = schema if filter_schema is None else filter_schema
    filter_schema_id = mso.lookup_schema(filter_schema)
    contract_filter_type = "bothWay" if filter_type == "both-way" else "oneWay"

    # Set path defaults, when object (contract or filter) is found append /{name} to base paths
    base_contract_path = "/templates/{0}/contracts".format(template_name)
    base_filter_path = "{0}/{1}/{2}".format(base_contract_path, contract_name, filter_key)
    contract_path = "{0}/-".format(base_contract_path)
    filter_path = "{0}/-".format(base_filter_path)

    # Get schema information.
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template by unique identifier "name".
    template_obj = next((item for item in schema_obj.get("templates") if item.get("name") == template_name), None)
    if not template_obj:
        existing_templates = [t.get("name") for t in schema_obj.get("templates")]
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template_name, ", ".join(existing_templates)))

    filter_ref = mso.filter_ref(schema_id=filter_schema_id, template=filter_template, filter=filter_name)

    # Get contract by unique identifier "name".
    contract_obj = next((item for item in template_obj.get("contracts") if item.get("name") == contract_name), None)
    if contract_obj:
        if contract_obj.get("filterType") != contract_filter_type:
            mso.fail_json(
                msg="Current filter type '{0}' for contract '{1}' is not allowed to change to '{2}'.".format(
                    contract_obj.get("filterType"), contract_name, contract_filter_type
                )
            )
        contract_path = "{0}/{1}".format(base_contract_path, contract_name)
        if filter_name:
            # Get filter by unique identifier "filterRef".
            filter_obj = next((item for item in contract_obj.get(filter_key) if item.get("filterRef") == filter_ref), None)
            if filter_obj:
                filter_path = "{0}/{1}".format(base_filter_path, filter_name)
                mso.update_filter_obj(contract_obj, filter_obj, filter_type)
                mso.existing = filter_obj

    if state == "query":
        if not contract_obj:
            existing_contracts = [c.get("name") for c in template_obj.get("contracts")]
            mso.fail_json(msg="Provided contract '{0}' does not exist. Existing contracts: {1}".format(contract_name, ", ".join(existing_contracts)))

        # If filter name is not provided, provide overview of all filter objects for the filter type.
        if not filter_name:
            mso.existing = contract_obj.get(filter_key)
            for filter_obj in mso.existing:
                mso.update_filter_obj(contract_obj, filter_obj, filter_type)

        elif not mso.existing:
            mso.fail_json(msg="FilterRef '{filter_ref}' not found".format(filter_ref=filter_ref))

        mso.exit_json()

    mso.previous = mso.existing

    if state == "absent":
        # Contracts need at least one filter left, remove contract if remove would lead 0 filters remaining.
        if contract_obj:
            if len(contract_obj.get(filter_key)) == 1:
                mso.existing = {}
                ops.append(dict(op="remove", path=contract_path))
            elif len(contract_obj.get(filter_key)) > 1:
                mso.existing = {}
                ops.append(dict(op="remove", path=filter_path))

    elif state == "present":
        contract_scope = "context" if contract_scope == "vrf" else contract_scope

        # Initialize "present" state filter variables
        if not filter_directives:
            # Avoid validation error: "Bad Request: (0)(1)(0) 'directives' is undefined on object
            if not filter_obj:
                filter_directives = ["none"]
            else:
                filter_directives = filter_obj.get("directives", ["none"])

        elif "policy_compression" in filter_directives:
            filter_directives[filter_directives.index("policy_compression")] = "no_stats"
        filter_payload = dict(
            filterRef=dict(
                filterName=filter_name,
                templateName=filter_template,
                schemaId=filter_schema_id,
            ),
            directives=filter_directives,
        )
        if filter_action:
            filter_payload.update(action=filter_action)
        if filter_action == "deny" and filter_priority:
            filter_payload.update(priorityOverride=PRIORITY_MAP.get(filter_priority))

        # If contract exist the operation should be set to replace else operation is add to create new contract.
        if contract_obj:
            if contract_display_name:
                ops.append(dict(op="replace", path=contract_path + "/displayName", value=contract_display_name))
            # Conditional statement 'description == ""' is needed to allow setting the description back to empty string.
            if description or description == "":
                ops.append(dict(op="replace", path=contract_path + "/description", value=description))
            if qos_level:
                # Conditional statement is needed to determine if "prio" exist in contract object.
                # An object can be created in 3.3 higher version without prio via the API.
                # In the GUI a default is set to "unspecified" and thus prio is always configured via GUI.
                # We can't set a default of "unspecified" because prior to version 3.3 qos_level is not supported,
                #  thus the logic is needed for both add and replace operation
                if contract_obj.get("prio"):
                    ops.append(dict(op="replace", path=contract_path + "/prio", value=qos_level))
                else:
                    ops.append(dict(op="add", path=contract_path + "/prio", value=qos_level))
            if contract_scope:
                ops.append(dict(op="replace", path=contract_path + "/scope", value=contract_scope))

            # If filter exist the operation should be set to replace else operation is add to create new filter.
            if filter_obj:
                ops.append(dict(op="replace", path=filter_path, value=filter_payload))
            else:
                ops.append(dict(op="add", path=filter_path, value=filter_payload))

        else:
            contract_display_name = contract_display_name if contract_display_name else contract_name
            # If contract_scope is not provided default to context to match GUI behaviour on create new contract.
            contract_scope = "context" if contract_scope is None else contract_scope
            contract_payload = dict(name=contract_name, displayName=contract_display_name, filterType=contract_filter_type, scope=contract_scope)
            if description:
                contract_payload.update(description=description)
            if qos_level:
                contract_payload.update(prio=qos_level)
            if filter_key == "filterRelationships":
                contract_payload.update(filterRelationships=[filter_payload])
            elif filter_key == "filterRelationshipsConsumerToProvider":
                contract_payload.update(filterRelationshipsConsumerToProvider=[filter_payload])
            elif filter_key == "filterRelationshipsProviderToConsumer":
                contract_payload.update(filterRelationshipsProviderToConsumer=[filter_payload])
            ops.append(dict(op="add", path=contract_path, value=contract_payload))

        mso.sanitize(filter_payload, collate=True, unwanted=["filterType", "contractScope", "contractFilterType"])

        # Update existing with filter (mso.sent) and contract information.
        mso.existing = mso.sent
        mso.existing["displayName"] = contract_display_name if contract_display_name else contract_obj.get("displayName")
        mso.existing["filterType"] = filter_type
        mso.existing["contractScope"] = contract_scope if contract_scope else contract_obj.get("scope")
        mso.existing["contractFilterType"] = contract_filter_type
        # Conditional statement 'description == ""' is needed to allow setting the description back to empty string.
        if description or (contract_obj and (contract_obj.get("description") or contract_obj.get("description") == "")):
            mso.existing["description"] = description if description or description == "" else contract_obj.get("description")
        # Conditional statement to check qos_level is defined or is present in the contract object.
        # qos_level is not supported prior to 3.3 thus this check in place, GUI uses default of "unspecified" from 3.3.
        # When default of "unspecified" is set, conditional statement can be simplified since "prio" always present.
        if qos_level or (contract_obj and contract_obj.get("prio")):
            mso.existing["prio"] = qos_level if qos_level else contract_obj.get("prio")

    if not module.check_mode and mso.existing != mso.previous:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
