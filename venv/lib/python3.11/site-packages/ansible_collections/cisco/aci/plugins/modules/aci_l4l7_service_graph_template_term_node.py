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
module: aci_l4l7_service_graph_template_term_node
version_added: "2.12.0"
short_description: Manage L4-L7 SGT Term Nodes (vns:AbsTermNodeCon, vns:AbsTermNodeProv and vns:AbsTermConn)
description:
- Manage L4-L7 Service Graph Template Term Nodes on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  service_graph:
    description:
    - The name of an existing Service graph.
    type: str
  node_name:
    description:
    - The name of the Term Node.
    type: str
    choices: [ T1, T2 ]
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
  description: More information about the internal APIC classes, B(vns:AbsTermNodeCon), B(vns:AbsTermNodeProv), B(vns:AbsTermConn)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new Term Node
  cisco.aci.aci_l4l7_service_graph_template_term_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: my_service_graph
    node_name: T1
    state: present
  delegate_to: localhost

- name: Query a Term Node
  cisco.aci.aci_l4l7_service_graph_template_term_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: my_service_graph
    node_name: T1
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a Term Node
  cisco.aci.aci_l4l7_service_graph_template_term_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: my_service_graph
    node_name: T1
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
        node_name=dict(type="str", choices=["T1", "T2"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "service_graph", "node_name"]],
            ["state", "present", ["tenant", "service_graph", "node_name"]],
        ],
    )

    tenant = module.params.get("tenant")
    service_graph = module.params.get("service_graph")
    state = module.params.get("state")
    node_name = module.params.get("node_name")

    aci = ACIModule(module)

    if node_name == "T1":
        term_class = "vnsAbsTermNodeCon"
        term_rn = "AbsTermNodeCon-T1"
        term_module_object = "T1"
        term_target_filter = {"name": "T1"}
        name = "T1"
    elif node_name == "T2":
        term_class = "vnsAbsTermNodeProv"
        term_rn = "AbsTermNodeProv-T2"
        term_module_object = "T2"
        term_target_filter = {"name": "T2"}
        name = "T2"

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
            aci_class=term_class,
            aci_rn=term_rn,
            module_object=term_module_object,
            target_filter=term_target_filter,
        ),
        child_classes=["vnsAbsTermConn"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=term_class,
            class_config=dict(name=name),
            child_configs=[
                dict(
                    vnsAbsTermConn=dict(
                        attributes=dict(name="1"),
                    ),
                ),
            ],
        )
        aci.get_diff(aci_class=term_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
