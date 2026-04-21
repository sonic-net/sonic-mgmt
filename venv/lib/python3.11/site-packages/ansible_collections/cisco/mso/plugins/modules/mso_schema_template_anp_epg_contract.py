#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_anp_epg_contract
short_description: Manage EPG contracts in schema templates
description:
- Manage EPG contracts in schema templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
- Akini Ross (@akinross)
options:
  schema:
    description:
    - The name of the Schema.
    type: str
    required: true
  template:
    description:
    - The name of the Template.
    type: str
    required: true
  anp:
    description:
    - The name of the ANP.
    type: str
    required: true
  epg:
    description:
    - The name of the EPG.
    type: str
    required: true
  force_replace:
    description:
    - Replaces all the configured contract(s) with the provided contract(s).
    - This option can only be used in combination with the O(contracts) option.
    - In combination with the O(state=absent) and without any contract configuration all configured static port(s) will be removed.
    type: bool
  contract:
    description:
    - The Contract associated to this EPG.
    - This option can not be used in combination with the I(contracts) option.
    type: dict
    suboptions:
      name:
        description:
        - The name of the Contract.
        required: true
        type: str
      schema:
        description:
        - The name of the Schema that defines the referenced Contract.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      template:
        description:
        - The name of the Template that defines the referenced Contract.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      type:
        description:
        - The type of the Contract.
        type: str
        required: true
        choices: [ consumer, provider ]
  contracts:
    description:
    - A list of Contracts associated to this EPG.
    - This option can not be used in combination with the O(contract) option.
    - All configured contract(s) will be replaced with the provided contract(s) when used with O(force_replace=true).
    - Only the provided contract(s) will be added, updated or removed when used with O(force_replace=false).
    - In combination with the O(state=query) all provided contract(s) must be found else the task will fail.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the Contract.
        required: true
        type: str
      schema:
        description:
        - The name of the Schema that defines the referenced Contract.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      template:
        description:
        - The name of the Template that defines the referenced Contract.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      type:
        description:
        - The type of the Contract.
        type: str
        required: true
        choices: [ consumer, provider ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_anp_epg
- module: cisco.mso.mso_schema_template_contract_filter
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a contract to an EPG
  cisco.mso.mso_schema_template_anp_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    contract:
      name: Contract 1
      type: consumer
    state: present

- name: Add 2 contracts to an EPG
  cisco.mso.mso_schema_template_anp_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    contracts:
      - name: Contract 1
        type: provider
      - name: Contract 1
        type: consumer
    state: present

- name: Replace all existing contracts on an EPG with 2 new contracts
  cisco.mso.mso_schema_template_anp_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    force_replace: true
    contracts:
      - name: Contract 2
        type: provider
      - name: Contract 2
        type: consumer
    state: present

- name: Query a specific Contract
  cisco.mso.mso_schema_template_anp_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    contract:
      name: Contract 1
      type: consumer
    state: query
  register: query_result

- name: Query a list of Contracts
  cisco.mso.mso_schema_template_anp_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    contracts:
      - name: Contract 2
        type: provider
      - name: Contract 2
        type: consumer
    state: query
  register: query_result

- name: Query all Contracts
  cisco.mso.mso_schema_template_anp_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    state: query
  register: query_result

- name: Remove a Contract
  cisco.mso.mso_schema_template_anp_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    contract:
      name: Contract 1
    state: absent

- name: Remove 2 contracts to an EPG
  cisco.mso.mso_schema_template_anp_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    contracts:
      - name: Contract 1
        type: provider
      - name: Contract 1
        type: consumer
    state: absent

- name: Remove all existing contracts from an EPG
  cisco.mso.mso_schema_template_anp_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    force_replace: true
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_contractref_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        epg=dict(type="str", required=True),
        force_replace=dict(type="bool"),
        contract=dict(type="dict", options=mso_contractref_spec()),
        contracts=dict(type="list", elements="dict", options=mso_contractref_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["contract", "contracts", "force_replace"], True],
            ["state", "present", ["contract", "contracts"], True],
        ],
        mutually_exclusive=[
            ["contract", "contracts"],
            ["contract", "force_replace"],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    force_replace = module.params.get("force_replace")
    contract = module.params.get("contract")
    contracts = module.params.get("contracts")
    state = module.params.get("state")

    mso = MSOModule(module)

    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)
    mso_schema.set_template_anp(anp)
    mso_schema.set_template_anp_epg(epg)

    # Schema dict is used as a cache store for schema id lookups
    # This is done to limit the amount of schema id lookups when schema is not specified for multiple contracts
    schema_cache = {mso_schema.schema_name: mso_schema.id}
    if contract:
        overwrite_contract_schema_and_template(mso, contract, schema, schema_cache, template)
    elif contracts:
        for contract_dict in contracts:
            overwrite_contract_schema_and_template(mso, contract_dict, schema, schema_cache, template)

    contracts_path = "/templates/{0}/anps/{1}/epgs/{2}/contractRelationships".format(template, anp, epg)
    contract_path = "{0}/-".format(contracts_path)
    ops = []

    if contract:
        contract_ref = mso.contract_ref(**contract)
        mso_schema.set_template_anp_epg_contract(contract_ref, contract.get("type"), False)
        if mso_schema.schema_objects.get("template_anp_epg_contract") is not None:
            mso.existing = get_contract_payload_from_schema(mso, mso_schema)
            contract_path = "{0}/{1}".format(contracts_path, mso_schema.schema_objects["template_anp_epg_contract"].index)
    else:
        found_contracts = []
        set_existing_contracts(mso, mso_schema)
        if contracts:
            for contract_details in contracts:
                contract_ref = mso.contract_ref(**contract_details)
                mso_schema.set_template_anp_epg_contract(contract_ref, contract_details.get("type"), False)
                if mso_schema.schema_objects.get("template_anp_epg_contract") is not None:
                    found_contracts.append(get_contract_payload_from_schema(mso, mso_schema))

    if state == "query":
        if contracts:
            if len(found_contracts) == len(contracts):
                mso.existing = found_contracts
            else:
                not_found_contracts = [
                    "Contract with Reference '{0}' and type '{1}' not found".format(mso.contract_ref(**contract), contract.get("type"))
                    for contract in contracts
                    if contract not in found_contracts
                ]
                mso.fail_json(msg=not_found_contracts)
        elif contract and not mso.existing:
            mso.fail_json(msg="Contract with Reference '{0}' and type '{1}' not found".format(contract_ref, contract.get("type")))
        mso.exit_json()

    mso.previous = mso.existing

    if state == "absent" and mso.existing:
        if contract:
            mso.sent = mso.proposed = {}
            ops.append(dict(op="remove", path=contract_path))
        elif force_replace:
            mso.sent = mso.proposed = []
            ops.append(dict(op="remove", path=contracts_path))
        else:
            mso.proposed = mso.existing.copy()
            remove_index = []
            for contract in contracts:
                payload = get_contract_payload(contract)
                if any(True if payload == found_contract else False for found_contract in found_contracts):
                    mso.proposed.remove(payload)
                    remove_index.append(mso.existing.index(payload))
            # The list index should not shift when removing contracts from the list
            # By sorting the indexes found in reverse order, we assure that the highest index is removed first by the NDO backend
            # This logic is to avoid removing the wrong contract
            for index in reversed(sorted(remove_index)):
                ops.append(dict(op="remove", path="{0}/{1}".format(contracts_path, index)))
            mso.sent = mso.proposed

    elif state == "present":
        if contract:
            mso.sanitize(get_contract_payload(contract), collate=True)
            if not mso.existing:
                ops.append(dict(op="add", path=contract_path, value=mso.sent))
        elif force_replace:
            mso.sent = mso.proposed = [get_contract_payload(contract) for contract in contracts]
            if mso.existing:
                ops.append(dict(op="replace", path=contracts_path, value=mso.sent))
            else:
                ops.append(dict(op="add", path=contracts_path, value=mso.sent))
        else:
            mso.sent = []
            mso.proposed = mso.existing.copy()
            for contract in contracts:
                payload = get_contract_payload(contract)
                if payload not in mso.existing:
                    mso.proposed.append(payload)
                # Only add the operation list if the contract is not already present
                # This is to avoid adding the same contract multiple times
                # Replace operation is not required because there are no attributes that can be changed except the contract itself
                if not force_replace and not any(True if payload == found_contract else False for found_contract in found_contracts):
                    ops.append(dict(op="add", path=contract_path, value=payload))
                    mso.sent.append(payload)

    mso.existing = mso.proposed

    if not module.check_mode and mso.proposed != mso.previous:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


def set_existing_contracts(mso, mso_schema):
    mso.existing = []
    for existing_contract in mso_schema.schema_objects["template_anp_epg"].details.get("contractRelationships"):
        mso.existing.append(
            dict(
                relationshipType=existing_contract.get("relationshipType"),
                contractRef=mso.dict_from_ref(existing_contract.get("contractRef")),
            )
        )


def get_contract_payload_from_schema(mso, mso_schema):
    return dict(
        relationshipType=mso_schema.schema_objects["template_anp_epg_contract"].details.get("relationshipType"),
        contractRef=mso.dict_from_ref(mso_schema.schema_objects["template_anp_epg_contract"].details.get("contractRef")),
    )


def get_contract_payload(contract):
    return dict(
        relationshipType=contract.get("type"),
        contractRef=dict(
            contractName=contract.get("name"),
            templateName=contract.get("template"),
            schemaId=contract.get("schema_id"),
        ),
    )


def overwrite_contract_schema_and_template(mso, contract, epg_schema_name, schema_cache, epg_template_name):
    if contract.get("schema") is None:
        contract["schema"] = epg_schema_name
        contract["schema_id"] = schema_cache.get(epg_schema_name)
    else:
        schema_id = schema_cache.get(contract.get("schema"))
        contract["schema_id"] = schema_id if schema_id else mso.lookup_schema(contract.get("schema"))

    if contract.get("template") is None:
        contract["template"] = epg_template_name
    else:
        contract["template"] = contract.get("template").replace(" ", "")


if __name__ == "__main__":
    main()
