#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}


DOCUMENTATION = r"""
---
module: mso_schema_site_contract_service_graph
short_description: Manage the service graph association with a contract in schema sites
description:
- Manage the service graph association with a contract in schema sites on Cisco ACI Multi-Site.
- This module is only compatible with NDO versions 3.7 and 4.2+. NDO versions 4.0 and 4.1 are not supported.
author:
- Sabari Jaganathan (@sajagana)
options:
  tenant:
    description:
    - The name of the tenant.
    type: str
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
  site:
    description:
    - The name of the site.
    type: str
    required: true
  service_graph_schema:
    description:
    - The name of the schema in which the service graph is located.
    type: str
  service_graph_template:
    description:
    - The name of the template in which the service graph is located.
    type: str
  service_graph:
    description:
    - The name of the service graph to associate with the site contract.
    type: str
  node_relationship:
    description:
    - A list of nodes and their connector details associated with the Service Graph.
    type: list
    elements: dict
    suboptions:
      cluster_interface_device:
        description:
        - The name of the cluster interface device.
        type: str
        required: true
        aliases: [ cluster_device, device, device_name ]
      provider_connector_cluster_interface:
        description:
        - The name of the cluster interface for the provider connector.
        type: str
        required: true
        aliases: [ provider_cluster_interface, provider_interface, provider_interface_name ]
      provider_connector_redirect_policy_tenant:
        description:
        - The name of the tenant for the provider connector redirect policy.
        type: str
        aliases: [ provider_redirect_policy_tenant, provider_tenant ]
      provider_connector_redirect_policy:
        description:
        - The name of the redirect policy for the provider connector.
        type: str
        aliases: [ provider_redirect_policy, provider_policy ]
      consumer_connector_cluster_interface:
        description:
        - The name of the cluster interface for the consumer connector.
        type: str
        required: true
        aliases: [ consumer_cluster_interface, consumer_interface, consumer_interface_name ]
      consumer_connector_redirect_policy_tenant:
        description:
        - The name of the tenant for the consumer connector redirect policy.
        type: str
        aliases: [ consumer_redirect_policy_tenant, consumer_tenant ]
      consumer_connector_redirect_policy:
        description:
        - The name of the redirect policy for the consumer connector.
        type: str
        aliases: [ consumer_redirect_policy, consumer_policy ]
      consumer_subnet_ips:
        description:
        - The list of subnet IPs for the consumer connector.
        - The subnet IPs option is only available for the load balancer devices.
        type: list
        elements: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_contract_service_graph
extends_documentation_fragment: cisco.mso.modules
"""


EXAMPLES = r"""
- name: Associate a service graph with a site contract
  cisco.mso.mso_schema_site_contract_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: ansible_tenant
    schema: ansible_schema
    template: ansible_template1
    site: ansible_test
    contract: Contract1
    service_graph_schema: ansible_schema
    service_graph_template: ansible_template1
    service_graph: sg
    node_relationship:
      - cluster_interface_device: ansible_tenant_firewall1
        provider_connector_cluster_interface: clu_if1
        provider_connector_redirect_policy: redirect_policy1
        consumer_connector_cluster_interface: clu_if1
        consumer_connector_redirect_policy: redirect_policy1
      - cluster_interface_device: ansible_tenant_adc
        provider_connector_cluster_interface: clu_if3
        provider_connector_redirect_policy: redirect_policy1
        consumer_connector_cluster_interface: clu_if3
        consumer_connector_redirect_policy: redirect_policy1
        consumer_subnet_ips: ["1.1.1.1/24", "4.4.4.4/24"]
      - cluster_interface_device: ansible_tenant_other
        provider_connector_cluster_interface: clu_if4
        provider_connector_redirect_policy: redirect_policy1
        consumer_connector_cluster_interface: clu_if4
        consumer_connector_redirect_policy: redirect_policy1
    state: present

- name: Associate a service graph with a cloud site contract
  cisco.mso.mso_schema_site_contract_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    tenant: ansible_tenant
    schema: ansible_schema
    template: ansible_template1
    site: ansible_test
    contract: Contract1
    service_graph_schema: ansible_schema
    service_graph_template: ansible_template1
    service_graph: sg
    state: present

- name: Query a site contract service graph with contract name
  cisco.mso.mso_schema_site_contract_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_schema
    template: ansible_template1
    contract: Contract1
    site: ansible_test
    state: query
  register: query_result

- name: Query all site contract service graphs associated with a site template
  cisco.mso.mso_schema_site_contract_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_schema
    template: ansible_template1
    site: ansible_test
    state: query
  register: query_result

- name: Remove a site contract service graph with contract name
  cisco.mso.mso_schema_site_contract_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: ansible_schema
    template: ansible_template1
    site: ansible_test
    contract: Contract1
    state: absent
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_schema_site_contract_service_graph_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        tenant=dict(type="str"),
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        contract=dict(type="str"),
        site=dict(type="str", required=True),
        service_graph_schema=dict(type="str"),
        service_graph_template=dict(type="str"),
        service_graph=dict(type="str"),
        node_relationship=dict(type="list", elements="dict", options=mso_schema_site_contract_service_graph_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["contract"]],
            ["state", "present", ["contract", "service_graph"]],
        ],
    )

    tenant = module.params.get("tenant")
    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    contract = module.params.get("contract")
    site = module.params.get("site")
    service_graph_schema = module.params.get("service_graph_schema")
    service_graph_template = module.params.get("service_graph_template")
    service_graph = module.params.get("service_graph")
    node_relationship = module.params.get("node_relationship")
    state = module.params.get("state")

    mso = MSOModule(module)

    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)

    service_graph_schema_id = schema_id = mso.lookup_schema(schema, True)
    service_graph_reference_schema = service_graph_schema or schema

    # Get service graph reference schema id if the service graph schema is not matching with the schema
    if service_graph_reference_schema != schema:
        service_graph_schema_id = mso.lookup_schema(service_graph_reference_schema, True)
        if service_graph_schema_id is None:
            mso.fail_json(msg="Provided service_graph_schema: '{0}' does not exist.".format(service_graph_schema))

    service_graph_reference_schema_id = service_graph_schema_id or schema_id
    service_graph_reference_template = service_graph_template or template

    # Get site id
    site_id = mso.lookup_site(site)
    mso_schema.set_site(template, site)
    mso_schema.set_site_contract(contract, False)

    if mso.site_type == "on-premise" and state == "present":
        # When site type is on-premise, both node_relationship and tenant are required
        if node_relationship is None and tenant is None:
            mso.fail_json(msg="The node_relationship and tenant attributes are required when state is present and site type is on-premise.")
        elif node_relationship is None:
            mso.fail_json(msg="The node_relationship attribute is required when state is present and site type is on-premise.")
        elif tenant is None:
            mso.fail_json(msg="The tenant attribute is required when state is present and site type is on-premise.")

    if contract and mso_schema.schema_objects["site_contract"] is not None:
        site_contract_service_graph = mso_schema.schema_objects["site_contract"].details.get("serviceGraphRelationship")
        if site_contract_service_graph and service_graph:
            site_contract_service_graph_name = site_contract_service_graph.get("serviceGraphRef").split("/")[-1]
            if site_contract_service_graph_name == service_graph:
                mso.existing = site_contract_service_graph
            else:
                mso.fail_json(msg="The service graph: {0} does not associated with the site contract: {1}.".format(service_graph, contract))
        elif site_contract_service_graph and service_graph is None:
            mso.existing = site_contract_service_graph
    elif contract is not None and mso_schema.schema_objects["site_contract"] is None:
        mso.fail_json(msg="The site contract: {0} does not exist.".format(contract))
    elif contract is None and mso_schema.schema_objects["site"].details.get("contracts"):
        mso.existing = [
            contract.get("serviceGraphRelationship")
            for contract in mso_schema.schema_objects["site"].details.get("contracts")
            if contract.get("serviceGraphRelationship")
        ]

    if state == "query":
        mso.exit_json()

    site_contract_service_graph_path = "/sites/{0}-{1}/contracts/{2}/serviceGraphRelationship".format(site_id, service_graph_reference_template, contract)

    ops = []
    mso.previous = mso.existing

    if state == "absent":
        mso.existing = {}
        ops.append(dict(op="remove", path=site_contract_service_graph_path))
    elif state == "present":
        service_graph_ref = dict(schemaId=service_graph_reference_schema_id, serviceGraphName=service_graph, templateName=service_graph_reference_template)
        service_node_relationship = []
        if mso.site_type == "on-premise" and node_relationship:
            for node_index, node in enumerate(node_relationship, 1):
                service_node_ref = dict(
                    schemaId=service_graph_reference_schema_id,
                    serviceGraphName=service_graph,
                    serviceNodeName="node{0}".format(node_index),
                    templateName=service_graph_reference_template,
                )

                consumer_subnet_ips_list = [dict(ip=subnet) for subnet in node.get("consumer_subnet_ips")] if node.get("consumer_subnet_ips") else []
                consumer_connector = dict(
                    clusterInterface=dict(
                        dn="uni/tn-{0}/lDevVip-{1}/lIf-{2}".format(
                            tenant, node.get("cluster_interface_device"), node.get("consumer_connector_cluster_interface")
                        )
                    ),
                    redirectPolicy=dict(
                        dn="uni/tn-{0}/svcCont/svcRedirectPol-{1}".format(
                            node.get("consumer_connector_redirect_policy_tenant") or tenant, node.get("consumer_connector_redirect_policy")
                        )
                    ),
                    subnets=consumer_subnet_ips_list,
                )
                provider_connector = dict(
                    clusterInterface=dict(
                        dn="uni/tn-{0}/lDevVip-{1}/lIf-{2}".format(
                            tenant, node.get("cluster_interface_device"), node.get("provider_connector_cluster_interface")
                        )
                    ),
                    redirectPolicy=dict(
                        dn="uni/tn-{0}/svcCont/svcRedirectPol-{1}".format(
                            node.get("provider_connector_redirect_policy_tenant") or tenant, node.get("provider_connector_redirect_policy")
                        )
                    ),
                )
                service_node_relationship.append(
                    dict(consumerConnector=consumer_connector, providerConnector=provider_connector, serviceNodeRef=service_node_ref)
                )

            payload = dict(serviceGraphRef=service_graph_ref, serviceNodesRelationship=service_node_relationship)
        elif mso.cloud_provider_type == "azure":
            mso_schema.set_site_service_graph(service_graph)
            service_nodes = mso_schema.schema_objects["site_service_graph"].details.get("serviceNodes", [])
            payload = dict(
                serviceGraphRef=service_graph_ref, serviceNodesRelationship=[dict(serviceNodeRef=sg_node.get("serviceNodeRef")) for sg_node in service_nodes]
            )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op="replace", path=site_contract_service_graph_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=site_contract_service_graph_path, value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
