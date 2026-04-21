#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_service_graph
short_description: Manage Service Graph in schema sites
description:
- Manage Service Graph in schema sites on Cisco ACI Multi-Site.
- This module is only supported in MSO/NDO version 3.3 and above.
author:
- Shreyas Srish (@shrsr)
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
  site:
    description:
    - The name of the site.
    type: str
    required: true
  tenant:
    description:
    - The name of the tenant.
    type: str
  service_graph:
    description:
    - The name of the Service Graph to manage.
    type: str
    aliases: [ name ]
  devices:
    description:
    - A list of devices to be associated with the Service Graph.
    type: list
    elements: dict
    suboptions:
      device_name:
        description:
        - The name of the device
        required: true
        type: str
        aliases: [ name ]
      provider_interface:
        description:
        - The name of the provider interface for the Azure CNC L4-L7 device.
        type: str
      provider_connector_type:
        description:
        - The provider connector type for the Azure CNC site service graph.
        - Defaults to C(none) when unset during creation.
        type: str
        choices: [ none, redirect, source_nat, destination_nat, source_and_destination_nat ]
      consumer_interface:
        description:
        - The name of the consumer interface for the Azure CNC L4-L7 device.
        type: str
      consumer_connector_type:
        description:
        - The consumer connector type for the Azure CNC site service graph.
        - Defaults to C(none) when unset during creation.
        type: str
        choices: [ none, redirect ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a Service Graph
  cisco.mso.mso_schema_site_service_graph_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: SG1
    site: site1
    tenant: tenant1
    devices:
      - name: ansible_test_firewall
      - name: ansible_test_adc
      - name: ansible_test_other
    state: present

- name: Add a Site service graph for the Azure cloud CNC
  cisco.mso.mso_schema_site_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: SG1
    site: site1
    tenant: tenant1
    devices:
      - name: ans_tnt_firewall1
        provider_connector_type: source_nat
        provider_interface: TP_FW_Inf1
        consumer_connector_type: redirect
        consumer_interface: TP_FW_Inf1
      - name: ans_tnt_app_lb
      - name: ans_tnt_other
        provider_connector_type: destination_nat
        consumer_connector_type: redirect
    state: present

- name: Remove a Service Graph
  cisco.mso.mso_schema_site_service_graph_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: SG1
    site: site1
    state: absent

- name: Query a specific Service Graph
  cisco.mso.mso_schema_site_service_graph_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: SG1
    site: site1
    state: query
  register: query_result

- name: Query all Service Graphs
  cisco.mso.mso_schema_site_service_graph_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    site: site1
    state: query
  register: query_result
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
    mso_service_graph_node_device_spec,
    service_node_ref_str_to_dict,
)
from ansible_collections.cisco.mso.plugins.module_utils.constants import AZURE_L4L7_CONNECTOR_TYPE_MAP


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        service_graph=dict(type="str", aliases=["name"]),
        tenant=dict(type="str"),
        site=dict(type="str", required=True),
        devices=dict(type="list", elements="dict", options=mso_service_graph_node_device_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["service_graph"]],
            ["state", "present", ["service_graph", "devices"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    service_graph = module.params.get("service_graph")
    devices = module.params.get("devices")
    site = module.params.get("site")
    tenant = module.params.get("tenant")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = schema_obj.get("templates")
    template_names = [t.get("name") for t in templates]
    if template not in template_names:
        mso.fail_json(
            msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template, templates=", ".join(template_names))
        )
    template_idx = template_names.index(template)

    # Get site
    site_id = mso.lookup_site(site)

    # Get site_idx
    if not schema_obj.get("sites"):
        mso.fail_json(msg="No site associated with template '{0}'. Associate the site with the template using mso_schema_site.".format(template))
    sites = [(s.get("siteId"), s.get("templateName")) for s in schema_obj.get("sites")]
    if (site_id, template) not in sites:
        mso.fail_json(msg="Provided site-template association '{0}-{1}' does not exist.".format(site, template))

    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = "{0}-{1}".format(site_id, template)

    mso.existing = {}
    service_graph_idx = None

    # Get Service Graph
    service_graph_ref = mso.service_graph_ref(schema_id=schema_id, template=template, service_graph=service_graph)
    service_graph_refs = [f.get("serviceGraphRef") for f in schema_obj.get("sites")[site_idx]["serviceGraphs"]]
    if service_graph is not None and service_graph_ref in service_graph_refs:
        service_graph_idx = service_graph_refs.index(service_graph_ref)
        mso.existing = schema_obj.get("sites")[site_idx]["serviceGraphs"][service_graph_idx]

    if state == "query":
        if service_graph is None:
            mso.existing = schema_obj.get("sites")[site_idx]["serviceGraphs"]
        elif service_graph is not None and service_graph_idx is None:
            mso.fail_json(msg="Service Graph '{service_graph}' not found".format(service_graph=service_graph))
        mso.exit_json()

    service_graphs_path = "/sites/{0}/serviceGraphs/-".format(site_template)
    service_graph_path = "/sites/{0}/serviceGraphs/{1}".format(site_template, service_graph)
    ops = []

    mso.previous = mso.existing
    if mso.previous.get("serviceNodes") is not None and len(mso.previous.get("serviceNodes")) > 0:
        for node in mso.previous.get("serviceNodes"):
            node["serviceNodeRef"] = service_node_ref_str_to_dict(node.get("serviceNodeRef"))

    devices_payload = []

    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=service_graph_path))

    elif state == "present":
        service_graphs = templates[template_idx]["serviceGraphs"]
        service_node_types_from_template = []
        for graph in service_graphs:
            if graph.get("name") == service_graph:
                service_node_types_from_template = graph["serviceNodes"]
                break

        user_number_devices = len(devices)
        number_of_nodes_in_template = len(service_node_types_from_template)
        if user_number_devices != number_of_nodes_in_template:
            mso.fail_json(
                msg="Service Graph '{0}' has '{1}' service node type(s) but '{2}' service node(s) were given for the service graph".format(
                    service_graph, number_of_nodes_in_template, user_number_devices
                )
            )

        if devices is not None:
            query_device_data = mso.lookup_service_node_device(site_id, tenant, device_name=None, service_node_type=None)
            for index, device in enumerate(devices):
                if query_device_data:
                    for device_data in query_device_data:
                        if device.get("device_name") == device_data.get("dn").split("/")[-1].split("-")[-1]:
                            device_payload = dict()
                            device_payload["device"] = dict(
                                dn=device_data.get("dn"),
                                funcType=device_data.get("funcType"),
                            )
                            device_payload["serviceNodeRef"] = dict(
                                serviceNodeName="node{0}".format(index + 1),
                                serviceGraphName=service_graph,
                                templateName=template,
                                schemaId=schema_id,
                            )

                            if mso.cloud_provider_type == "azure":
                                consumer_interface = device.get("consumer_interface")
                                provider_interface = device.get("provider_interface")
                                provider_connector_type = device.get("provider_connector_type")
                                consumer_connector_type = device.get("consumer_connector_type")

                                if (
                                    device_data.get("deviceVendorType") == "NATIVELB"
                                    and device_data.get("devType") == "application"
                                    and (
                                        consumer_interface is not None
                                        or provider_interface is not None
                                        or provider_connector_type is not None
                                        or consumer_connector_type is not None
                                    )
                                ):
                                    # Application Load Balancer - Consumer Interface, Consumer Connector Type,
                                    # Provider Interface, Provider Connector Type - not supported
                                    mso.fail_json(
                                        msg="Unsupported attributes: provider_connector_type, provider_interface, "
                                        + "consumer_connector_type, consumer_interface should be 'None' for the "
                                        + "Application Load Balancer device."
                                    )
                                elif (
                                    device_data.get("deviceVendorType") == "NATIVELB"
                                    and device_data.get("devType") == "network"
                                    and (consumer_interface is not None or provider_interface is not None)
                                ):
                                    # Network Load Balancer - Consumer Interface, Provider Interface - not supported
                                    mso.fail_json(
                                        msg="Unsupported attributes: provider_interface and consumer_interface should "
                                        + "be 'None' for the Network Load Balancer device."
                                    )
                                elif (
                                    device_data.get("deviceVendorType") == "ADC"
                                    and device_data.get("devType") == "CLOUD"
                                    and (provider_connector_type is not None or consumer_connector_type is not None)
                                ):
                                    # Third-Party Load Balancer - Consumer Connector Type,
                                    # Provider Connector Type - not supported
                                    mso.fail_json(
                                        msg="Unsupported attributes: provider_connector_type and "
                                        + "consumer_connector_type should be 'None' for the "
                                        + "Third-Party Load Balancer."
                                    )

                                # (FW) Third-Party Firewall - Consumer Interface, Consumer Connector Type,
                                # Provider Interface, Provider Connector Type - supported
                                device_payload["consumerInterface"] = consumer_interface
                                device_payload["providerInterface"] = provider_interface
                                device_payload["providerConnectorType"] = AZURE_L4L7_CONNECTOR_TYPE_MAP.get(provider_connector_type)
                                device_payload["consumerConnectorType"] = AZURE_L4L7_CONNECTOR_TYPE_MAP.get(consumer_connector_type)

                            devices_payload.append(device_payload)

        payload = dict(
            serviceGraphRef=dict(
                serviceGraphName=service_graph,
                templateName=template,
                schemaId=schema_id,
            ),
            serviceNodes=devices_payload,
        )

        mso.sanitize(payload, collate=True)

        if not mso.existing:
            # The site service graph reference will be added automatically when the site is associated with the template
            # So the add(create) part will not be used for the NDO v4.2
            ops.append(dict(op="add", path=service_graphs_path, value=payload))
        else:
            ops.append(dict(op="replace", path=service_graph_path, value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
