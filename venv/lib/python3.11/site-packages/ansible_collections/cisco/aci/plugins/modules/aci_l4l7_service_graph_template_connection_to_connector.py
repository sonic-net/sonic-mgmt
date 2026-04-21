#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l4l7_service_graph_template_connection_to_connector
version_added: "2.12.0"
short_description: Manage L4-L7 Service Graph Template Connections between function nodes and terminal nodes (vns:RsAbsConnectionConns)
description:
- Manage L4-L7 Service Graph Template Connections to define traffic flows between function nodes and terminal nodes.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  service_graph:
    description:
    - The name of an existing Service Graph.
    type: str
  connection_name:
    description:
    - The name of an existing vns:AbsConnection object.
    type: str
  direction:
    description:
    - The direction of the connection.
    - If this links to a terminal node, both vns:RsAbsConnectionConns will use the same direction.
    - Otherwise one vns:RsAbsConnectionConns will be consumer, and the other will be provider.
    type: str
    choices: [ consumer, provider ]
  connected_node:
    description:
    - The name of an existing node.
    - Omit this variable for connections to terminal nodes.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
notes:
- The I(tenant), I(service_graph) and I(connection_name) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l4l7_service_graph_template)
  and M(cisco.aci.aci_l4l7_service_graph_template_abs_conn) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l4l7_service_graph_template
- module: cisco.aci.aci_l4l7_service_graph_template_abs_connection
- module: cisco.aci.aci_l4l7_service_graph_template_node
- name: APIC Management Information Model reference
  description: More information about the internal APIC class, B(vns:RsAbsConnectionConns)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new connection
  cisco.aci.aci_l4l7_service_graph_template_connection_to_connector:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: test-graph
    direction: provider
    connection_name: C1
    state: present
  delegate_to: localhost

- name: Query a connection
  cisco.aci.aci_l4l7_service_graph_template_connection_to_connector:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: test-graph
    direction: provider
    connection_name: C1
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a connection
  cisco.aci.aci_l4l7_service_graph_template_connection_to_connector:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: test-graph
    direction: provider
    connection_name: C1
    state: absent
  delegate_to: localhost
"""

RETURN = r"""
current:
  description: The existing configuration from the APIC after the module has finished
  returned: success
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production environment",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
error:
  description: The error information as returned from the APIC
  returned: failure
  type: dict
  sample:
    {
        "code": "122",
        "text": "unknown managed object class foo"
    }
raw:
  description: The raw output returned by the APIC REST API (xml or json)
  returned: parse error
  type: str
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
sent:
  description: The actual/minimal configuration pushed to the APIC
  returned: info
  type: list
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment"
            }
        }
    }
previous:
  description: The original configuration from the APIC before the module has started
  returned: info
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
proposed:
  description: The assembled configuration from the user-provided parameters
  returned: info
  type: dict
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment",
                "name": "production"
            }
        }
    }
filter_string:
  description: The filter string used for the request
  returned: failure or debug
  type: str
  sample: ?rsp-prop-include=config-only
method:
  description: The HTTP method used for the request to the APIC
  returned: failure or debug
  type: str
  sample: POST
response:
  description: The HTTP response from the APIC
  returned: failure or debug
  type: str
  sample: OK (30 bytes)
status:
  description: The HTTP status from the APIC
  returned: failure or debug
  type: int
  sample: 200
url:
  description: The HTTP url used for the request to the APIC
  returned: failure or debug
  type: str
  sample: https://10.11.12.13/api/mo/uni/tn-production.json
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        service_graph=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        connection_name=dict(type="str"),
        direction=dict(type="str", choices=["consumer", "provider"]),
        connected_node=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "service_graph", "connection_name", "direction"]],
            ["state", "present", ["tenant", "service_graph", "connection_name", "direction"]],
        ],
    )

    tenant = module.params.get("tenant")
    service_graph = module.params.get("service_graph")
    state = module.params.get("state")
    connection_name = module.params.get("connection_name")
    direction = module.params.get("direction")
    connected_node = module.params.get("connected_node")

    aci = ACIModule(module)
    if connected_node:
        tdn = "uni/tn-{0}/AbsGraph-{1}/AbsNode-{2}/AbsFConn-{3}".format(tenant, service_graph, connected_node, direction)
    elif direction == "consumer":
        tdn = "uni/tn-{0}/AbsGraph-{1}/AbsTermNodeCon-T1/AbsTConn".format(tenant, service_graph)
    elif direction == "provider":
        tdn = "uni/tn-{0}/AbsGraph-{1}/AbsTermNodeProv-T2/AbsTConn".format(tenant, service_graph)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vnsAbsGraph",
            aci_rn="AbsGraph-{0}".format(service_graph),
            module_object=service_graph,
            target_filter={"name": service_graph},
        ),
        subclass_2=dict(
            aci_class="vnsAbsConnection",
            aci_rn="AbsConnection-{0}".format(connection_name),
            module_object=connection_name,
            target_filter={"name": connection_name},
        ),
        subclass_3=dict(
            aci_class="vnsRsAbsConnectionConns",
            aci_rn="rsabsConnectionConns-[{0}]".format(tdn),
            module_object=tdn,
            target_filter={"tDn": tdn},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="vnsRsAbsConnectionConns",
            class_config=dict(tDn=tdn),
        )
        aci.get_diff(aci_class="vnsRsAbsConnectionConns")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
