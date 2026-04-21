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
module: aci_l4l7_device_selection_interface_context
version_added: "2.12.0"
short_description: Manage L4-L7 Device Selection Policy Logical Interface Contexts (vns:LIfCtx)
description:
- Manage L4-L7 Device Selection Policy Logical Interface Contexts
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  contract:
    description:
    - The name of an existing contract.
    type: str
    aliases: [ contract_name ]
  graph:
    description:
    - The name of an existing Service Graph Template.
    type: str
    aliases: [ service_graph, service_graph_name ]
  node:
    description:
    - The name of an existing Service Graph Node.
    type: str
    aliases: [ node_name ]
  context:
    description:
    - The name of the logical interface context.
    type: str
  l3_destination:
    description:
    - Whether the context is a Layer3 destination.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
    aliases: [ l3_dest ]
  permit_log:
    description:
    - Whether to log permitted traffic.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  bridge_domain:
    description:
    - The Bridge Domain to bind to the Context.
    type: str
    aliases: [ bd, bd_name ]
  bridge_domain_tenant:
    description:
    - The tenant the Bridge Domain resides in.
    - Omit this variable if both context and Bridge Domain are in the same tenant.
    - Intended use case is for when the Bridge Domain is in the common tenant, but the context is not.
    type: str
    aliases: [ bd_tenant ]
  logical_device:
    description:
    - The Logical Device to bind the context to.
    type: str
  logical_interface:
    description:
    - The Logical Interface to bind the context to.
    type: str
  redirect_policy:
    description:
    - The Redirect Policy to bind the context to.
    type: str
  permit_handoff:
    description:
    - Indicates whether to allow handoff of traffic to the associated logical interface.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  acl:
    description:
    - Specifies whether an Access Control List (ACL) is applied to the logical interface.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  description:
    description:
    - A brief description for the Logical Interface Context.
    type: str
  rule_type:
    description:
    - Indicates whether the context uses a specific rule type for traffic handling.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  l3out:
    description:
    - The name of the Layer 3 Outside (L3Out) object.
    type: str
  l3out_tenant:
    description:
    - The tenant in which the L3Out resides.
    - Omit this variable if both context and L3Out are in the same tenant.
    type: str
  external_epg:
    description:
    - The name of the External Network Instance Profile (External EPG or ExtEpg) associated with the L3Out.
    type: str
  redistribute:
    description:
    - A list of routing protocols whose routes should be redistributed.
    type: list
    elements: str
    choices: [ bgp, ospf, connected, static ]
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
- The I(tenant), I(graph), I(contract) and I(node) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l4l7_service_graph_template), M(cisco.aci.aci_contract)
  and M(cisco.aci.aci_l4l7_service_graph_template_node) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l4l7_service_graph_template
- module: cisco.aci.aci_contract
- module: cisco.aci.aci_l4l7_service_graph_template_node
- name: APIC Management Information Model reference
  description: More information about the internal APIC class, B(vns:LIfCtx)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new interface context
  cisco.aci.aci_l4l7_device_selection_interface_context:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    contract: my_contract
    graph: my_graph
    node: my_node
    context: provider
    state: present
  delegate_to: localhost

- name: Query an interface context
  cisco.aci.aci_l4l7_device_selection_interface_context:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    contract: my_contract
    graph: my_graph
    node: my_node
    context: consumer
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all interface contexts
  cisco.aci.aci_l4l7_device_selection_interface_context:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete an interface context
  cisco.aci.aci_l4l7_device_selection_interface_context:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    contract: my_contract
    graph: my_graph
    node: my_node
    context: provider
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
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        context=dict(type="str"),
        l3_destination=dict(type="bool", aliases=["l3_dest"]),
        permit_log=dict(type="bool"),
        bridge_domain=dict(type="str", aliases=["bd", "bd_name"]),
        bridge_domain_tenant=dict(type="str", aliases=["bd_tenant"]),
        logical_device=dict(type="str"),
        logical_interface=dict(type="str"),
        redirect_policy=dict(type="str"),
        permit_handoff=dict(type="bool"),
        acl=dict(type="bool"),
        description=dict(type="str"),
        rule_type=dict(type="bool"),
        l3out=dict(type="str"),
        l3out_tenant=dict(type="str"),
        external_epg=dict(type="str"),
        redistribute=dict(type="list", elements="str", choices=["bgp", "ospf", "connected", "static"]),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "contract", "graph", "node", "context"]],
            ["state", "present", ["tenant", "contract", "graph", "node", "context"]],
        ],
        required_together=[
            ("l3out", "external_epg"),
        ],
        mutually_exclusive=[
            ("bridge_domain", "l3out"),
            ("bridge_domain", "l3out_tenant"),
            ("bridge_domain", "external_epg"),
            ("bridge_domain", "redistribute"),
            ("l3out", "bridge_domain_tenant"),
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    contract = module.params.get("contract")
    graph = module.params.get("graph")
    node = module.params.get("node")
    context = module.params.get("context")
    l3_destination = aci.boolean(module.params.get("l3_destination"))
    permit_log = aci.boolean(module.params.get("permit_log"))
    bridge_domain = module.params.get("bridge_domain")
    bridge_domain_tenant = module.params.get("bridge_domain_tenant")
    l3out = module.params.get("l3out")
    l3out_tenant = module.params.get("l3out_tenant")
    external_epg = module.params.get("external_epg")
    redistribute = module.params.get("redistribute")
    logical_device = module.params.get("logical_device")
    logical_interface = module.params.get("logical_interface")
    redirect_policy = module.params.get("redirect_policy")
    permit_handoff = aci.boolean(module.params.get("permit_handoff"))
    acl = aci.boolean(module.params.get("acl"))
    description = module.params.get("description")
    rule_type = aci.boolean(module.params.get("rule_type"))

    ldev_ctx_rn = "ldevCtx-c-{0}-g-{1}-n-{2}".format(contract, graph, node) if (contract, graph, node) != (None, None, None) else None

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
        subclass_2=dict(
            aci_class="vnsLIfCtx",
            aci_rn="lIfCtx-c-{0}".format(context),
            module_object=context,
            target_filter={"connNameOrLbl": context},
        ),
        child_classes=["vnsRsLIfCtxToBD", "vnsRsLIfCtxToLIf", "vnsRsLIfCtxToSvcRedirectPol", "vnsRsLIfCtxToInstP"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if bridge_domain:
            if bridge_domain_tenant is None:
                bridge_domain_tenant = tenant
            bd_tdn = "uni/tn-{0}/BD-{1}".format(bridge_domain_tenant, bridge_domain)
            child_configs.append({"vnsRsLIfCtxToBD": {"attributes": {"tDn": bd_tdn}}})
        else:
            bd_tdn = None
        if l3out:
            if l3out_tenant is None:
                l3out_tenant = tenant
            if redistribute is not None:
                redistribute = ",".join(redistribute)
            l3out_tdn = "uni/tn-{0}/out-{1}/instP-{2}".format(l3out_tenant, l3out, external_epg)
            child_configs.append({"vnsRsLIfCtxToInstP": {"attributes": {"tDn": l3out_tdn, "redistribute": redistribute}}})
        else:
            l3out_tdn = None
        if logical_interface:
            log_intf_tdn = "uni/tn-{0}/lDevVip-{1}/lIf-{2}".format(tenant, logical_device, logical_interface)
            child_configs.append({"vnsRsLIfCtxToLIf": {"attributes": {"tDn": log_intf_tdn}}})
        else:
            log_intf_tdn = None
        if redirect_policy:
            redir_pol_tdn = "uni/tn-{0}/svcCont/svcRedirectPol-{1}".format(tenant, redirect_policy)
            child_configs.append({"vnsRsLIfCtxToSvcRedirectPol": {"attributes": {"tDn": redir_pol_tdn}}})
        else:
            redir_pol_tdn = None
        # Validate if existing and remove child objects when do not match provided configuration
        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            for child in aci.existing[0].get("vnsLIfCtx", {}).get("children", {}):
                if child.get("vnsRsLIfCtxToBD") and child.get("vnsRsLIfCtxToBD").get("attributes").get("tDn") != bd_tdn:
                    # Appending to child_config list not possible because of APIC Error 103: child (Rn) of class vnsRsLIfCtxToBD is already attached.
                    # A seperate delete request to dn of the vnsRsLIfCtxToBD is needed to remove the object prior to adding to child_configs.
                    # child_configs.append(
                    #     {
                    #         "vnsRsLIfCtxToBD": {
                    #             "attributes": {
                    #                 "dn": child.get("vnsRsLIfCtxToBD").get("attributes").get("dn"),
                    #                 "status": "deleted",
                    #             }
                    #         }
                    #     }
                    # )
                    aci.api_call(
                        "DELETE",
                        "{0}/api/mo/uni/tn-{1}/ldevCtx-c-{2}-g-{3}-n-{4}/lIfCtx-c-{5}/rsLIfCtxToBD.json".format(
                            aci.base_url, tenant, contract, graph, node, context
                        ),
                    )
                elif child.get("vnsRsLIfCtxToInstP") and child.get("vnsRsLIfCtxToInstP").get("attributes").get("tDn") != l3out_tdn:
                    # Appending to child_config list not possible because of APIC Error 103: child (Rn) of class vnsRsLIfCtxToInstP is already attached.
                    # A seperate delete request to dn of the vnsRsLIfCtxToInstP is needed to remove the object prior to adding to child_configs.
                    aci.api_call(
                        "DELETE",
                        "{0}/api/mo/uni/tn-{1}/ldevCtx-c-{2}-g-{3}-n-{4}/lIfCtx-c-{5}/rsLIfCtxToInstP.json".format(
                            aci.base_url, tenant, contract, graph, node, context
                        ),
                    )
                elif child.get("vnsRsLIfCtxToLIf") and child.get("vnsRsLIfCtxToLIf").get("attributes").get("tDn") != log_intf_tdn:
                    child_configs.append(
                        {
                            "vnsRsLIfCtxToLIf": {
                                "attributes": {
                                    "dn": child.get("vnsRsLIfCtxToLIf").get("attributes").get("dn"),
                                    "status": "deleted",
                                }
                            }
                        }
                    )
                elif child.get("vnsRsLIfCtxToSvcRedirectPol") and child.get("vnsRsLIfCtxToSvcRedirectPol").get("attributes").get("tDn") != redir_pol_tdn:
                    child_configs.append(
                        {
                            "vnsRsLIfCtxToSvcRedirectPol": {
                                "attributes": {
                                    "dn": child.get("vnsRsLIfCtxToSvcRedirectPol").get("attributes").get("dn"),
                                    "status": "deleted",
                                }
                            }
                        }
                    )
        aci.payload(
            aci_class="vnsLIfCtx",
            class_config=dict(
                connNameOrLbl=context,
                l3Dest=l3_destination,
                permitLog=permit_log,
                permitHandoff=permit_handoff,
                acl=acl,
                descr=description,
                ruleType=rule_type,
            ),
            child_configs=child_configs,
        )
        aci.get_diff(aci_class="vnsLIfCtx")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
