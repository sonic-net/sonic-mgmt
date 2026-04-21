#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_anp_epg_intra_epg_contract
short_description: Manage Intra-EPG Contract on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Intra-EPG Contract on Cisco Nexus Dashboard Orchestrator (NDO).
author:
- Sabari Jaganathan (@sajagana)
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
    - The name of the Application Profile.
    type: str
    aliases: [ application_profile ]
    required: true
  epg:
    description:
    - The name of the Endpoint Group.
    type: str
    aliases: [ endpoint_group ]
    required: true
  contract:
    description:
    - A contract associated to this Intra-EPG Contract.
    type: dict
    suboptions:
      name:
        description:
        - The name of the Contract to associate with.
        required: true
        type: str
        aliases: [ contract_name ]
      schema:
        description:
        - The schema that defines the referenced Contract.
        - If this parameter is unspecified, it defaults to the current O(schema).
        type: str
        aliases: [ contract_schema ]
      template:
        description:
        - The template that defines the referenced Contract.
        - If this parameter is unspecified, it defaults to the current O(template).
        type: str
        aliases: [ contract_template ]
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(schema) must exist before using this module in your playbook.
  Use M(cisco.mso.mso_schema) to create the Schema.
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.mso_schema_template) to create the Template.
- The O(anp) must exist before using this module in your playbook.
  Use M(cisco.mso.mso_schema_template_anp) to create the Application Profile.
- The O(epg) must exist before using this module in your playbook.
  Use M(cisco.mso.mso_schema_template_anp_epg) to create the Endpoint Group.
- The O(contract) must exist before using this module in your playbook.
  Use M(cisco.mso.mso_schema_template_contract_filter) to create the Contract with Filter.
seealso:
- module: cisco.mso.mso_schema
- module: cisco.mso.mso_schema_template
- module: cisco.mso.mso_schema_template_anp
- module: cisco.mso.mso_schema_template_anp_epg
- module: cisco.mso.mso_schema_template_contract_filter
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Bind an schema template contract with EPG Intra-EPG Contracts
  cisco.mso.mso_schema_template_anp_epg_intra_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_schema
    template: ansible_template
    anp: ansible_anp
    epg: ansible_epg
    contract:
      schema: ansible_contract_schema
      template: ansible_contract_template
      name: ansible_contract_name
    state: present

- name: Query an Intra-EPG Contract with contract details
  cisco.mso.mso_schema_template_anp_epg_intra_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_schema
    template: ansible_template
    anp: ansible_anp
    epg: ansible_epg
    contract:
      schema: ansible_contract_schema
      template: ansible_contract_template
      name: ansible_contract_name
    state: query
  register: query_with_contract_details

- name: Query an Intra-EPG Contract with only contract name
  cisco.mso.mso_schema_template_anp_epg_intra_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_schema
    template: ansible_template
    anp: ansible_anp
    epg: ansible_epg
    contract:
      name: ansible_contract_name
    state: query
  register: query_with_contract_name

- name: Query all Intra-EPG Contracts
  cisco.mso.mso_schema_template_anp_epg_intra_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_schema
    template: ansible_template
    anp: ansible_anp
    epg: ansible_epg
    state: query
  register: query_all

- name: Remove an Intra-EPG Contract with contract details
  cisco.mso.mso_schema_template_anp_epg_intra_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_schema
    template: ansible_template
    anp: ansible_anp
    epg: ansible_epg
    contract:
      schema: ansible_contract_schema
      template: ansible_contract_template
      name: ansible_contract_name
    state: absent

- name: Remove an Intra-EPG Contract with only contract name
  cisco.mso.mso_schema_template_anp_epg_intra_epg_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_schema
    template: ansible_template
    anp: ansible_anp
    epg: ansible_epg
    contract:
      name: ansible_contract_name
    state: absent
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema


def get_intra_epg_contracts_ref(intra_epg_contracts, name, schema_id, template):
    res_intra_epg_contracts_ref = []
    for intra_epg_contract in intra_epg_contracts:
        if intra_epg_contract.get("contractRef") == "/schemas/{0}/templates/{1}/contracts/{2}".format(schema_id, template, name):
            res_intra_epg_contracts_ref.append(intra_epg_contract.get("contractRef"))
        elif name is None:
            res_intra_epg_contracts_ref.append(intra_epg_contract.get("contractRef"))

    return res_intra_epg_contracts_ref


def main():
    argument_spec = mso_argument_spec()

    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", aliases=["application_profile"], required=True),
        epg=dict(type="str", aliases=["endpoint_group"], required=True),
        contract=dict(
            type="dict",
            options=dict(
                name=dict(type="str", aliases=["contract_name"], required=True),
                schema=dict(type="str", aliases=["contract_schema"]),
                template=dict(type="str", aliases=["contract_template"]),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["contract"]],
            ["state", "present", ["contract"]],
        ],
    )

    schema = module.params.get("schema")
    template = str(module.params.get("template")).replace(" ", "")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    contract = module.params.get("contract") if module.params.get("contract") else {}
    state = module.params.get("state")

    mso = MSOModule(module)

    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)
    mso_schema.set_template_anp(anp)
    mso_schema.set_template_anp_epg(epg)

    contract_template = (contract.get("template") if contract.get("template") else template).replace(" ", "")
    contract_schema_id = MSOSchema(mso, contract.get("schema"), contract_template).id if contract.get("schema") is not None else None

    matching_contracts = get_intra_epg_contracts_ref(
        mso_schema.schema_objects.get("template_anp_epg", {}).details.get("intraEpgContracts", []),
        contract.get("name"),
        schema_id=contract_schema_id if contract_schema_id else mso_schema.id,
        template=contract_template,
    )

    contract_ref = "/schemas/{0}/templates/{1}/contracts/{2}".format(
        contract_schema_id if contract_schema_id else mso_schema.id, contract_template, contract.get("name")
    )

    if contract_ref in matching_contracts:
        mso.existing = dict(contractRef=contract_ref)
        mso.previous = dict(contractRef=contract_ref)

    if state != "query":
        intra_epg_contract_path = "/templates/{0}/anps/{1}/epgs/{2}/intraEpgContracts/{3}".format(
            template, anp, epg, matching_contracts.index(contract_ref) if contract_ref in matching_contracts else "-"
        )
    else:
        mso.existing = [dict(contractRef=contract_ref) for contract_ref in matching_contracts]  # When the state is query

    ops = []
    if state == "present":
        mso_values = mso.existing if mso.existing else dict(contractRef=contract_ref)
        mso.sanitize(mso_values, collate=False, required=["contractRef"])
        ops.append(dict(op="replace" if mso.existing else "add", path=intra_epg_contract_path, value=mso_values))
    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path=intra_epg_contract_path))

    if not module.check_mode and ops:
        # Returns No Contract - 204
        mso.request(mso_schema.path, method="PATCH", data=ops)

        mso_schema = MSOSchema(mso, schema, template)
        mso_schema.set_template(template)
        mso_schema.set_template_anp(anp)
        mso_schema.set_template_anp_epg(epg)

        matching_contracts = get_intra_epg_contracts_ref(
            mso_schema.schema_objects.get("template_anp_epg", {}).details.get("intraEpgContracts", []),
            contract.get("name"),
            schema_id=contract_schema_id if contract_schema_id else mso_schema.id,
            template=contract_template,
        )

        if matching_contracts and contract_ref in matching_contracts:
            mso.existing = dict(contractRef=contract_ref)  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
