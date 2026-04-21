#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Tim Cragg (@timcragg)
# Copyright: (c) 2025, Shreyas Srish (@shrsr)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l4l7_service_graph_template_connection
version_added: "2.12.0"
short_description: Manage L4-L7 Service Graph Template Abs Connections (vns:AbsConnection)
description:
- Manage Layer 4 to Layer 7 (L4-L7) Service Graph Template Connections.
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
    - The name of the connection.
    type: str
  direct_connect:
    description:
    - Whether to enable direct connections.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  unicast_route:
    description:
    - Whether to enable unicast routing.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  adjacency_type:
    description:
    - Whether the adjacency is Layer2 or Layer3.
    - The APIC defaults to C(l2) when unset during creation.
    type: str
    choices: [ l2, l3 ]
  connector_direction:
    description:
    - The connector direction.
    - The APIC defaults to C(unknown) when unset during creation.
    type: str
    choices: [ provider, consumer, unknown ]
  connection_type:
    description:
    - The connection type.
    - The APIC defaults to C(external) when unset during creation.
    type: str
    choices: [ internal, external ]
  description:
    description:
    - The description for the Service Graph Template connection.
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
- cisco.aci.owner
notes:
- The I(tenant) and I(service_graph) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_l4l7_service_graph_template) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l4l7_service_graph_template
- name: APIC Management Information Model reference
  description: More information about the internal APIC class, B(vns:AbsConnection)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new connection
  cisco.aci.aci_l4l7_service_graph_template_connection:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: my_graph
    connection_name: C1
    state: present
  delegate_to: localhost

- name: Query a connection
  cisco.aci.aci_l4l7_service_graph_template_connection:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: my_graph
    connection_name: C1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all connections
  cisco.aci.aci_l4l7_service_graph_template_connection:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a connection
  cisco.aci.aci_l4l7_service_graph_template_connection:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: my_graph
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        service_graph=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        connection_name=dict(type="str"),
        direct_connect=dict(type="bool"),
        unicast_route=dict(type="bool"),
        adjacency_type=dict(type="str", choices=["l2", "l3"]),
        connector_direction=dict(type="str", choices=["provider", "consumer", "unknown"]),
        connection_type=dict(type="str", choices=["internal", "external"]),
        description=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "service_graph", "connection_name"]],
            ["state", "present", ["tenant", "service_graph", "connection_name"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    service_graph = module.params.get("service_graph")
    state = module.params.get("state")
    connection_name = module.params.get("connection_name")
    unicast_route = aci.boolean(module.params.get("unicast_route"))
    adjacency_type = module.params.get("adjacency_type").upper() if module.params.get("adjacency_type") is not None else None
    direct_connect = aci.boolean(module.params.get("direct_connect"))
    connector_direction = module.params.get("connector_direction")
    connection_type = module.params.get("connection_type")
    description = module.params.get("description")

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
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="vnsAbsConnection",
            class_config=dict(
                name=connection_name,
                adjType=adjacency_type,
                directConnect=direct_connect,
                unicastRoute=unicast_route,
                connType=connection_type,
                connDir=connector_direction,
                descr=description,
            ),
        )
        aci.get_diff(aci_class="vnsAbsConnection")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
