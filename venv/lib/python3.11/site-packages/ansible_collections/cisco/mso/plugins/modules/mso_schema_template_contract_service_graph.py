#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_contract_service_graph
short_description: Manage the service graph association with a contract in schema template
description:
- Manage the service graph association with a contract in schema template on Cisco ACI Multi-Site.
- The Contract Service Graph parameter is supported on versions of MSO/NDO that are 3.3 or greater.
- The recommended approach is to use M(cisco.mso.ndo_schema_template_contract_service_chain) rather than the Contract Service Graph.
- Service Chaining is supported only on ND v3.1 (NDO v4.2.3) and later versions.

author:
- Akini Ross (@akinross)
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
    - The name of the contract.
    type: str
    required: true
  service_graph:
    description:
    - The service graph to associate with this contract.
    type: str
  service_graph_template:
    description:
    - The template name in which the service graph is located.
    type: str
  service_graph_schema:
    description:
    - The schema name in which the service graph is located.
    type: str
  service_nodes:
    description:
    - A list of nodes and their connector details associated with the Service Graph.
    - The order of the list matches the node id ordering in GUI, so first entry in list will be match node 1.
    type: list
    elements: dict
    suboptions:
      provider:
        description:
        - The name of the Bridge Domain.
        required: true
        type: str
      consumer:
        description:
        - The name of the Bridge Domain.
        required: true
        type: str
      connector_object_type:
        description:
        - The connector ACI object type of the node.
        type: str
        default: bd
        choices: [ bd ]
      provider_schema:
        description:
        - The schema name in which the provider is located.
        type: str
      provider_template:
        description:
         - The template name in which the provider is located.
        type: str
      consumer_schema:
        description:
        - The schema name in which the consumer is located.
        type: str
      consumer_template:
        description:
         - The template name in which the consumer is located.
        type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_contract_filter
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new contract service graph
  cisco.mso.mso_schema_template_contract_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    contract: Contract 1
    service_graph: SG1
    service_graph_nodes:
      - provider: b1
        consumer: b2
    filter: Filter 1
    state: present

- name: Remove a contract service graph
  cisco.mso.mso_schema_template_contract_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    contract: Contract 1
    service_graph: SG1
    state: absent

- name: Query a contract service graph
  cisco.mso.mso_schema_template_contract_service_graph:
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
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_service_graph_connector_spec
from ansible_collections.cisco.mso.plugins.module_utils.constants import SERVICE_NODE_CONNECTOR_MAP


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        contract=dict(type="str", required=True),
        service_graph=dict(type="str"),
        service_graph_template=dict(type="str"),
        service_graph_schema=dict(type="str"),
        service_nodes=dict(type="list", elements="dict", options=mso_service_graph_connector_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["service_graph"]],
            ["state", "present", ["service_graph", "service_nodes"]],
        ],
    )

    schema = module.params.get("schema")
    template_name = module.params.get("template").replace(" ", "")
    contract_name = module.params.get("contract")
    service_graph_name = module.params.get("service_graph")
    service_graph_template = module.params.get("service_graph_template")
    service_graph_schema = module.params.get("service_graph_schema")
    service_nodes = module.params.get("service_nodes")

    state = module.params.get("state")

    mso = MSOModule(module)

    # Initialize variables
    ops = []
    service_graph_obj = None

    # Set path defaults for create logic, if object (contract or filter) is found replace the "-" for specific value
    base_contract_path = "/templates/{0}/contracts".format(template_name)
    service_graph_path = "{0}/{1}/serviceGraphRelationship".format(base_contract_path, contract_name)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    template_obj = next((item for item in schema_obj.get("templates") if item.get("name") == template_name), None)
    if not template_obj:
        mso.fail_json(
            msg="Provided template '{0}' does not exist. Existing templates: {1}".format(
                template_name, ", ".join([t.get("name") for t in schema_obj.get("templates")])
            )
        )

    # Get contract
    contract_obj = next((item for item in template_obj.get("contracts") if item.get("name") == contract_name), None)
    if contract_obj:
        # Get service graph if it exists in contract
        if contract_obj.get("serviceGraphRelationship"):
            service_graph_obj = contract_obj.get("serviceGraphRelationship")
            mso.update_service_graph_obj(service_graph_obj)
            mso.existing = service_graph_obj
    else:
        mso.fail_json(
            msg="Provided contract '{0}' does not exist. Existing contracts: {1}".format(
                contract_name, ", ".join([c.get("name") for c in template_obj.get("contracts")])
            )
        )

    if state == "query":
        mso.exit_json()

    mso.previous = mso.existing

    if state == "absent":
        if contract_obj.get("serviceGraphRelationship"):
            mso.existing = {}
            ops.append(dict(op="remove", path=service_graph_path))

    elif state == "present":
        service_nodes_relationship = []
        service_graph_template = service_graph_template.replace(" ", "") if service_graph_template else template_name
        service_graph_schema = service_graph_schema if service_graph_schema else schema
        service_graph_schema_id, service_graph_schema_path, service_graph_schema_obj = mso.query_schema(service_graph_schema)

        # Validation to check if amount of service graph nodes provided is matching the service graph template.
        # The API allows providing more or less service graph nodes behaviour but the GUI does not.
        service_graph_template_obj = next((item for item in service_graph_schema_obj.get("templates") if item.get("name") == service_graph_template), None)
        if not service_graph_template_obj:
            mso.fail_json(
                msg="Provided template '{0}' does not exist. Existing templates: {1}".format(
                    template_name, ", ".join([t.get("name") for t in service_graph_schema_obj.get("templates")])
                )
            )
        service_graph_schema_obj = next((item for item in service_graph_template_obj.get("serviceGraphs") if item.get("name") == service_graph_name), None)
        if service_graph_schema_obj:
            if len(service_nodes) < len(service_graph_schema_obj.get("serviceNodes")):
                mso.fail_json(
                    msg="Not enough service nodes defined, {0} service node(s) provided when {1} needed.".format(
                        len(service_nodes), len(service_graph_schema_obj.get("serviceNodes"))
                    )
                )
            elif len(service_nodes) > len(service_graph_schema_obj.get("serviceNodes")):
                mso.fail_json(
                    msg="Too many service nodes defined, {0} service nodes provided when {1} needed.".format(
                        len(service_nodes), len(service_graph_schema_obj.get("serviceNodes"))
                    )
                )
        else:
            mso.fail_json(msg="Provided service graph '{0}' does not exist.".format(service_graph_name))

        for node_id, service_node in enumerate(service_nodes, 0):
            # Consumer and provider share connector details (so provider/consumer could have separate details in future)
            connector_details = SERVICE_NODE_CONNECTOR_MAP.get(service_node.get("connector_object_type"))
            provider_schema = mso.lookup_schema(service_node.get("provider_schema")) if service_node.get("provider_schema") else schema_id
            provider_template = service_node.get("provider_template").replace(" ", "") if service_node.get("provider_template") else template_name
            consumer_schema = mso.lookup_schema(service_node.get("consumer_schema")) if service_node.get("consumer_schema") else schema_id
            consumer_template = service_node.get("consumer_template").replace(" ", "") if service_node.get("consumer_template") else template_name

            service_nodes_relationship.append(
                {
                    "serviceNodeRef": dict(
                        schemaId=service_graph_schema_id,
                        templateName=service_graph_template,
                        serviceGraphName=service_graph_name,
                        serviceNodeName=service_graph_schema_obj.get("serviceNodes")[node_id].get("name"),
                    ),
                    "providerConnector": {
                        "connectorType": connector_details.get("connector_type"),
                        "{0}Ref".format(connector_details.get("id")): {
                            "schemaId": provider_schema,
                            "templateName": provider_template,
                            "{0}Name".format(connector_details.get("id")): service_node.get("provider"),
                        },
                    },
                    "consumerConnector": {
                        "connectorType": connector_details.get("connector_type"),
                        "{0}Ref".format(connector_details.get("id")): {
                            "schemaId": consumer_schema,
                            "templateName": consumer_template,
                            "{0}Name".format(connector_details.get("id")): service_node.get("consumer"),
                        },
                    },
                }
            )

        service_graph_payload = dict(
            serviceGraphRef=dict(serviceGraphName=service_graph_name, templateName=service_graph_template, schemaId=service_graph_schema_id),
            serviceNodesRelationship=service_nodes_relationship,
        )

        # If service graph exist the operation should be set to "replace" else operation is "add" to create new
        if service_graph_obj:
            ops.append(dict(op="replace", path=service_graph_path, value=service_graph_payload))
        else:
            ops.append(dict(op="add", path=service_graph_path, value=service_graph_payload))

        mso.existing = mso.sent = service_graph_payload

    if not module.check_mode and mso.existing != mso.previous:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
