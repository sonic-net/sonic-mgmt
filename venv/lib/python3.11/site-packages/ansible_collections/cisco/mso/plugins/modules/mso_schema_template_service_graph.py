#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_service_graph
short_description: Manage Service Graph in schema templates
description:
- Manage Service Graph in schema templates on Cisco ACI Multi-Site.
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
  service_graph:
    description:
    - The name of the Service Graph to manage.
    type: str
    aliases: [ name ]
  description:
    description:
    - The description of Service Graph.
    type: str
    default: ''
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  service_nodes:
    description:
    - A list of node types to be associated with the Service Graph.
    type: list
    elements: dict
    suboptions:
      type:
        description:
        - The type of node
        required: true
        type: str
  filter_after_first_node:
    description:
    - The filter applied after the first node.
    type: str
    choices: [ allow_all, filters_from_contract ]
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
- name: Add a new Service Graph
  cisco.mso.mso_schema_template_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: graph1
    service_nodes:
      - type: firewall
      - type: other
      - type: load-balancer
    state: present

- name: Remove a Service Graph
  cisco.mso.mso_schema_template_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: graph1
    state: absent

- name: Query a specific Service Graph
  cisco.mso.mso_schema_template_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: graph1
    state: query
  register: query_result

- name: Query all Service Graphs
  cisco.mso.mso_schema_template_service_graph:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_service_graph_node_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        service_graph=dict(type="str", aliases=["name"]),
        description=dict(type="str", default=""),
        display_name=dict(type="str"),
        service_nodes=dict(type="list", elements="dict", options=mso_service_graph_node_spec()),
        filter_after_first_node=dict(type="str", choices=["allow_all", "filters_from_contract"]),
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
    template = module.params.get("template").replace(" ", "")
    service_graph = module.params.get("service_graph")
    display_name = module.params.get("display_name")
    description = module.params.get("description")
    service_nodes = module.params.get("service_nodes")
    filter_after_first_node = module.params.get("filter_after_first_node")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(
            msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template, templates=", ".join(templates))
        )
    template_idx = templates.index(template)

    mso.existing = {}
    service_graph_idx = None

    # Get Service Graphs
    service_graphs = [f.get("name") for f in schema_obj.get("templates")[template_idx]["serviceGraphs"]]
    if service_graph in service_graphs:
        service_graph_idx = service_graphs.index(service_graph)
        mso.existing = schema_obj.get("templates")[template_idx]["serviceGraphs"][service_graph_idx]

    if state == "query":
        if service_graph is None:
            mso.existing = schema_obj.get("templates")[template_idx]["serviceGraphs"]
        if service_graph is not None and service_graph_idx is None:
            mso.fail_json(msg="Service Graph '{service_graph}' not found".format(service_graph=service_graph))
        mso.exit_json()

    service_graphs_path = "/templates/{0}/serviceGraphs/-".format(template)
    service_graph_path = "/templates/{0}/serviceGraphs/{1}".format(template, service_graph)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=service_graph_path))

    elif state == "present":
        nodes_payload = []
        service_node_index = 0

        if filter_after_first_node == "allow_all":
            filter_after_first_node = "allow-all"
        elif filter_after_first_node == "filters_from_contract":
            filter_after_first_node = "filters-from-contract"

        if display_name is None:
            display_name = service_graph

        # Get service nodes
        query_node_data = mso.query_service_node_types()
        service_node_types = [f.get("name") for f in query_node_data]
        if service_nodes is not None:
            for node in service_nodes:
                node_name = node.get("type")
                if node_name in service_node_types:
                    service_node_index = service_node_index + 1
                    service_node_name = "node{0}".format(service_node_index)
                    for node_data in query_node_data:
                        if node_data["name"] == node_name:
                            payload = dict(
                                name=service_node_name,
                                serviceNodeTypeId=node_data.get("id"),
                                index=service_node_index,
                                serviceNodeRef=dict(
                                    serviceNodeName=service_node_name,
                                    serviceGraphName=service_graph,
                                    templateName=template,
                                    schemaId=schema_id,
                                ),
                            )
                            if node_data.get("uuid"):
                                payload.update(uuid=node_data.get("uuid"))
                            nodes_payload.append(payload)
                else:
                    mso.fail_json(
                        "Provided service node type '{node_name}' does not exist. Existing service node types include: {node_types}".format(
                            node_name=node_name, node_types=", ".join(service_node_types)
                        )
                    )

        payload = dict(
            name=service_graph,
            displayName=display_name,
            description=description,
            nodeFilter=filter_after_first_node,
            serviceGraphRef=dict(
                serviceGraphName=service_graph,
                templateName=template,
                schemaId=schema_id,
            ),
            serviceNodes=nodes_payload,
        )

        mso.sanitize(payload, collate=True)

        if not mso.existing:
            ops.append(dict(op="add", path=service_graphs_path, value=payload))
        else:
            ops.append(dict(op="replace", path=service_graph_path, value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
