#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_vrf_contract
short_description: Manage vrf contracts in schema templates
description:
- Manage vrf contracts in schema templates on Cisco ACI Multi-Site.
author:
- Cindy Zhao (@cizhao)
version_added: '0.0.8'
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template to change.
    type: str
    required: true
  vrf:
    description:
    - The name of the VRF.
    type: str
    required: true
  contract:
    description:
    - A contract associated to this VRF.
    type: dict
    suboptions:
      name:
        description:
        - The name of the Contract to associate with.
        required: true
        type: str
      schema:
        description:
        - The schema that defines the referenced contract.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      template:
        description:
        - The template that defines the referenced contract.
        type: str
      type:
        description:
        - The type of contract.
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
- module: cisco.mso.mso_schema_template_vrf
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a contract to a VRF
  cisco.mso.mso_schema_template_vrf_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF 1
    contract:
      name: Contract 1
      type: consumer
    state: present

- name: Remove a Contract
  cisco.mso.mso_schema_template_vrf_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF 1
    contract:
      name: Contract 1
      type: consumer
    state: absent

- name: Query a specific Contract
  cisco.mso.mso_schema_template_vrf_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF 1
    contract:
      name: Contract 1
      type: consumer
    state: query
  register: query_result

- name: Query all Contracts
  cisco.mso.mso_schema_template_vrf_contract:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF 1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_contractref_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        vrf=dict(type="str", required=True),
        contract=dict(type="dict", options=mso_contractref_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
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
    template = module.params.get("template").replace(" ", "")
    vrf = module.params.get("vrf")
    contract = module.params.get("contract")
    if contract is not None and contract.get("template") is not None:
        contract["template"] = contract.get("template").replace(" ", "")
    state = module.params.get("state")

    mso = MSOModule(module)
    if contract:
        if contract.get("schema") is None:
            contract["schema"] = schema
        contract["schema_id"] = mso.lookup_schema(contract.get("schema"))
        if contract.get("template") is None:
            contract["template"] = template

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))
    template_idx = templates.index(template)

    # Get VRF
    vrfs = [e.get("name") for e in schema_obj.get("templates")[template_idx]["vrfs"]]
    if vrf not in vrfs:
        mso.fail_json(msg="Provided vrf '{vrf}' does not exist. Existing vrfs: {vrfs}".format(vrf=vrf, vrfs=", ".join(vrfs)))
    vrf_idx = vrfs.index(vrf)
    vrf_obj = schema_obj.get("templates")[template_idx]["vrfs"][vrf_idx]

    if not vrf_obj.get("vzAnyEnabled"):
        mso.fail_json(msg="vzAny attribute on vrf '{0}' is disabled.".format(vrf))

    # Get Contract
    contract_path = None
    if contract:
        provider_contracts = [c.get("contractRef") for c in schema_obj.get("templates")[template_idx]["vrfs"][vrf_idx]["vzAnyProviderContracts"]]
        consumer_contracts = [c.get("contractRef") for c in schema_obj.get("templates")[template_idx]["vrfs"][vrf_idx]["vzAnyConsumerContracts"]]
        contract_ref = mso.contract_ref(**contract)
        if contract_ref in provider_contracts and contract.get("type") == "provider":
            contract_idx = provider_contracts.index(contract_ref)
            contract_path = "/templates/{0}/vrfs/{1}/vzAnyProviderContracts/{2}".format(template, vrf, contract_idx)
            mso.existing = schema_obj.get("templates")[template_idx]["vrfs"][vrf_idx]["vzAnyProviderContracts"][contract_idx]
        if contract_ref in consumer_contracts and contract.get("type") == "consumer":
            contract_idx = consumer_contracts.index(contract_ref)
            contract_path = "/templates/{0}/vrfs/{1}/vzAnyConsumerContracts/{2}".format(template, vrf, contract_idx)
            mso.existing = schema_obj.get("templates")[template_idx]["vrfs"][vrf_idx]["vzAnyConsumerContracts"][contract_idx]
        if mso.existing.get("contractRef"):
            mso.existing["contractRef"] = mso.dict_from_ref(mso.existing.get("contractRef"))
            mso.existing["relationshipType"] = contract.get("type")

    if state == "query":
        if not contract:
            provider_contracts = [
                dict(contractRef=mso.dict_from_ref(c.get("contractRef")), relationshipType="provider")
                for c in schema_obj.get("templates")[template_idx]["vrfs"][vrf_idx]["vzAnyProviderContracts"]
            ]
            consumer_contracts = [
                dict(contractRef=mso.dict_from_ref(c.get("contractRef")), relationshipType="consumer")
                for c in schema_obj.get("templates")[template_idx]["vrfs"][vrf_idx]["vzAnyConsumerContracts"]
            ]
            mso.existing = provider_contracts + consumer_contracts
        elif not mso.existing:
            mso.fail_json(msg="Contract '{0}' not found".format(contract.get("name")))

        mso.exit_json()

    if contract.get("type") == "provider":
        contracts_path = "/templates/{0}/vrfs/{1}/vzAnyProviderContracts/-".format(template, vrf)
    if contract.get("type") == "consumer":
        contracts_path = "/templates/{0}/vrfs/{1}/vzAnyConsumerContracts/-".format(template, vrf)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing and contract_path:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=contract_path))

    elif state == "present":
        payload = dict(
            contractRef=dict(
                contractName=contract.get("name"),
                templateName=contract.get("template"),
                schemaId=contract.get("schema_id"),
            ),
        )

        mso.sanitize(payload, collate=True)

        if mso.existing and contract_path:
            ops.append(dict(op="replace", path=contract_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=contracts_path, value=mso.sent))

        mso.existing = mso.proposed
        mso.existing["relationshipType"] = contract.get("type")

    if not module.check_mode and mso.proposed != mso.previous:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
