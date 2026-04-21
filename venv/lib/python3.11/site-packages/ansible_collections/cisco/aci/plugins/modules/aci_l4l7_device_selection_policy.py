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
module: aci_l4l7_device_selection_policy
version_added: "2.12.0"
short_description: Manage L4-L7 Device Selection Policies (vns:LDevCtx)
description:
- Manage L4-L7 Device Selection Policies
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  contract:
    description:
    - The name of an existing contract.
    - The APIC defaults to C(any) when unset during creation.
    type: str
    aliases: [ contract_name ]
  graph:
    description:
    - The name of an existing service graph.
    - The APIC defaults to C(any) when unset during creation.
    type: str
    aliases: [ service_graph, service_graph_name ]
  node:
    description:
    - The name of an existing L4-L7 node.
    - The APIC defaults to C(any) when unset during creation.
    type: str
    aliases: [ node_name ]
  device:
    description:
    - The name of the L4-L7 Device to bind to the policy.
    type: str
  context:
    description:
    - The context name.
    type: str
  description:
    description:
    - A brief description for the Device Selection Policy.
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
- The I(tenant), I(contract), I(graph), I(device) and I(node) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_contract), M(cisco.aci.aci_l4l7_service_graph), M(cisco.aci.aci_l4l7_device) and
  M(cisco.aci.aci_l4l7_service_graph_template_node) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_contract
- module: cisco.aci.aci_l4l7_service_graph
- module: cisco.aci.aci_l4l7_device
- module: cisco.aci.aci_l4l7_service_graph_template_node
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vns:LDevCtx)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new device selection policy
  cisco.aci.aci_l4l7_device_selection_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    contract: my_contract
    graph: my_graph
    node: my_node
    state: present
  delegate_to: localhost

- name: Query a device selection policy
  cisco.aci.aci_l4l7_device_selection_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    contract: my_contract
    graph: my_graph
    node: my_node
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all device selection policies
  cisco.aci.aci_l4l7_device_selection_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a device selection policy
  cisco.aci.aci_l4l7_device_selection_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    contract: my_contract
    graph: my_graph
    node: my_node
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
        contract=dict(type="str", aliases=["contract_name"]),
        graph=dict(type="str", aliases=["service_graph", "service_graph_name"]),
        node=dict(type="str", aliases=["node_name"]),
        device=dict(type="str"),
        context=dict(type="str"),
        description=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "contract", "graph", "node"]],
            ["state", "present", ["tenant", "contract", "graph", "node"]],
        ],
    )

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    contract = module.params.get("contract")
    graph = module.params.get("graph")
    node = module.params.get("node")
    device = module.params.get("device")
    context = module.params.get("context")
    description = module.params.get("description")

    ldev_ctx_rn = "ldevCtx-c-{0}-g-{1}-n-{2}".format(contract, graph, node) if (contract, graph, node) != (None, None, None) else None

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vnsLDevCtx",
            aci_rn=ldev_ctx_rn,
            module_object=ldev_ctx_rn,
            target_filter={"dn": ldev_ctx_rn},
        ),
        child_classes=["vnsRsLDevCtxToLDev"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if device:
            device_tdn = "uni/tn-{0}/lDevVip-{1}".format(tenant, device)
            child_configs.append({"vnsRsLDevCtxToLDev": {"attributes": {"tDn": device_tdn}}})
        else:
            device_tdn = None
        # Validate if existing and remove child objects when do not match provided configuration
        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            for child in aci.existing[0].get("vnsLDevCtx", {}).get("children", {}):
                if child.get("vnsRsLDevCtxToLDev") and child.get("vnsRsLDevCtxToLDev").get("attributes").get("tDn") != device_tdn:
                    child_configs.append(
                        {
                            "vnsRsLDevCtxToLDev": {
                                "attributes": {
                                    "dn": child.get("vnsRsLDevCtxToLDev").get("attributes").get("dn"),
                                    "status": "deleted",
                                }
                            }
                        }
                    )
        aci.payload(
            aci_class="vnsLDevCtx",
            class_config=dict(
                ctrctNameOrLbl=contract,
                graphNameOrLbl=graph,
                nodeNameOrLbl=node,
                context=context,
                descr=description,
            ),
            child_configs=child_configs,
        )
        aci.get_diff(aci_class="vnsLDevCtx")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
