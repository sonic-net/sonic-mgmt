#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "certified",
}

DOCUMENTATION = r"""
---
module: aci_l3out
short_description: Manage Layer 3 Outside (L3Out) objects (l3ext:Out)
description:
- Manage Layer 3 Outside (L3Out) on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - Name of L3Out being created.
    type: str
    aliases: [ l3out_name, name ]
  vrf:
    description:
    - Name of the VRF being associated with the L3Out.
    - SR-MPLS Infra L3out requires the VRF to be 'overlay-1'.
    type: str
    aliases: [ vrf_name ]
  domain:
    description:
    - Name of the external L3 domain being associated with the L3Out.
    type: str
    aliases: [ ext_routed_domain_name, routed_domain ]
  dscp:
    description:
    - The target Differentiated Service (DSCP) value.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
    aliases: [ target ]
  route_control:
    description:
    - Route Control enforcement direction. The only allowed values are export or import,export.
    - The APIC defaults to C(export) when unset during creation.
    type: list
    elements: str
    choices: [ export, import ]
    aliases: [ route_control_enforcement ]
  mpls:
    description:
    - Indicate whether MPLS (Multi-Protocol Label Switching) is enabled or not.
    - The APIC defaults to C(no) when unset during creation.
    - SR-MPLS is only supported in APIC v5.0 and above.
    - The child classes C(mplsExtP), C(mplsRsLabelPol) and C(l3extProvLbl) will be displayed in output only when C(yes).
    type: str
    choices: [ "no", "yes" ]
  l3protocol:
    description:
    - Routing protocol for the L3Out.
    - Protocols already associated with an l3out must be provided again when the l3out is modified if the associated protocols are to be kept.
    - The Protocols are otherwise deleted if not provided each time an l3out is modified.
    - First example, to add BGP protocol to an l3out with OSPF protocol, the user must enter C([ bgp, ospf ]) even though "ospf" was provided before.
    - Second example, to change the protocol from OSPF to EIGRP, the user must simply enter C([ eigrp ]) and the previous OSPF protocol will be deleted.
    - To remove all existing protocols, the user must enter C([ static ]).
    - SR-MPLS Infra L3out requires the l3protocol to be 'bgp'.
    type: list
    elements: str
    choices: [ bgp, eigrp, ospf, pim, static ]
  ospf:
    description:
    - Parameters for the OSPF protocol.
    type: dict
    suboptions:
      area_cost:
        description:
        - The OSPF area cost.
        - The APIC defaults to C(1) when unset during creation.
        type: int
      area_ctrl:
        description:
        - The controls of redistribution and summary LSA generation into NSSA and Stub areas.
        - The APIC defaults to C(redistribute,summary) when unset during creation.
        type: list
        elements: str
        choices: [ redistribute, summary, suppress-fa, unspecified ]
      area_id:
        description:
        - The OSPF Area ID.
        - An area is a logical collection of OSPF networks, routers, and links that have the same area identification.
        - A router within an area must maintain a topological database for the area to which it belongs.
        - The router doesn't have detailed information about network topology outside of its area, thereby reducing the size of its database.
        - Areas limit the scope of route information distribution. It is not possible to do route update filtering within an area.
        - The link-state database (LSDB) of routers within the same area must be synchronized and be exactly the same.
        - However, route summarization and filtering is possible between different areas.
        - The main benefit of creating areas is a reduction in the number of routes to propagate-by the filtering and the summarization of routes.
        - Areas are identified by an area ID.
        - Cisco IOS software supports area IDs expressed in IP address format or decimal format, for example, area 0.0.0.0 is equal to area 0.
        - The APIC defaults to C(1) when unset during creation.
        type: str
      area_type:
        description:
        - The OSPF area type.
        - The APIC defaults to C(nssa) when unset during creation.
        type: str
        choices: [ nssa, regular, stub ]
      description:
        description:
        - Specifies the description of a policy component.
        type: str
        aliases: [ descr ]
      multipod_internal:
        description:
        - Start OSPF in WAN instance instead of default.
        - The APIC defaults to C(no) when unset during creation.
        type: str
        choices: [ "no", "yes" ]
      name_alias:
        description:
        - The alias for the current object. This relates to the nameAlias field in ACI.
        type: str
  asn:
    description:
    - The AS number for the L3Out.
    - Only applicable when using 'eigrp' as the l3protocol.
    type: int
    aliases: [ as_number ]
  description:
    description:
    - Description for the L3Out.
    type: str
    aliases: [ descr ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- The C(tenant) and C(domain) and C(vrf) used must exist before using this module in your playbook.
- The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_domain) and M(cisco.aci.aci_vrf) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_domain
- module: cisco.aci.aci_vrf
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:Out).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Rostyslav Davydenko (@rost-d)
- Gaspard Micol (@gmicol)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new L3Out
  cisco.aci.aci_l3out:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    name: prod_l3out
    description: L3Out for Production tenant
    domain: l3dom_prod
    vrf: prod
    l3protocol: ospf
    ospf:
      area_cost: 1
      area_ctrl: [summary, redistribute]
      area_id: 0.0.0.1
      area_type: regular
      multipod_internal: 'no'
    state: present
  delegate_to: localhost

- name: Delete L3Out
  cisco.aci.aci_l3out:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    name: prod_l3out
    state: absent
  delegate_to: localhost

- name: Query L3Out information
  cisco.aci.aci_l3out:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    name: prod_l3out
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all L3Outs
  cisco.aci.aci_l3out:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_all_result
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
    aci_owner_spec,
)
from ansible_collections.cisco.aci.plugins.module_utils.aci import ospf_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        l3out=dict(type="str", aliases=["l3out_name", "name"]),  # Not required for querying all objects
        domain=dict(type="str", aliases=["ext_routed_domain_name", "routed_domain"]),
        vrf=dict(type="str", aliases=["vrf_name"]),
        description=dict(type="str", aliases=["descr"]),
        route_control=dict(
            type="list",
            elements="str",
            choices=["export", "import"],
            aliases=["route_control_enforcement"],
        ),
        mpls=dict(type="str", choices=["no", "yes"]),
        dscp=dict(
            type="str",
            choices=[
                "AF11",
                "AF12",
                "AF13",
                "AF21",
                "AF22",
                "AF23",
                "AF31",
                "AF32",
                "AF33",
                "AF41",
                "AF42",
                "AF43",
                "CS0",
                "CS1",
                "CS2",
                "CS3",
                "CS4",
                "CS5",
                "CS6",
                "CS7",
                "EF",
                "VA",
                "unspecified",
            ],
            aliases=["target"],
        ),
        l3protocol=dict(
            type="list",
            elements="str",
            choices=["bgp", "eigrp", "ospf", "pim", "static"],
        ),
        ospf=dict(type="dict", options=ospf_spec()),
        asn=dict(type="int", aliases=["as_number"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["l3out", "tenant"]],
            ["state", "present", ["l3out", "tenant", "domain", "vrf"]],
        ],
    )

    aci = ACIModule(module)

    l3out = module.params.get("l3out")
    domain = module.params.get("domain")
    dscp = module.params.get("dscp")
    description = module.params.get("description")
    route_control = module.params.get("route_control")
    mpls = module.params.get("mpls")
    vrf = module.params.get("vrf")
    l3protocol = module.params.get("l3protocol")
    ospf = module.params.get("ospf")
    asn = module.params.get("asn")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    name_alias = module.params.get("name_alias")

    if l3protocol:
        if "eigrp" in l3protocol and asn is None:
            module.fail_json(msg="Parameter 'asn' is required when l3protocol is 'eigrp'")
        if "eigrp" not in l3protocol and asn is not None:
            module.warn("Parameter 'asn' is only applicable when l3protocol is 'eigrp'. The ASN will be ignored")
        if "ospf" not in l3protocol and ospf is not None:
            module.warn("Parameter 'ospf' is only applicable when l3protocol is 'ospf'. The OPSF specifications will be ignored")

    enforce_ctrl = None
    if route_control is not None:
        if len(route_control) == 1 and route_control[0] == "import":
            aci.fail_json("The route_control parameter is invalid: allowed options are export or import,export only")
        else:
            enforce_ctrl = ",".join(route_control)

    child_classes = [
        "l3extRsL3DomAtt",
        "l3extRsEctx",
        "bgpExtP",
        "ospfExtP",
        "eigrpExtP",
        "pimExtP",
    ]

    child_configs = [
        dict(l3extRsL3DomAtt=dict(attributes=dict(tDn="uni/l3dom-{0}".format(domain)))),
        dict(l3extRsEctx=dict(attributes=dict(tnFvCtxName=vrf))),
    ]

    if tenant == "infra" and mpls == "yes":
        if l3protocol != ["bgp"] and state == "present":
            module.fail_json(msg="The l3protocol parameter must be 'bgp' when tenant is 'infra' and mpls is 'yes'")
        if vrf != "overlay-1" and state == "present":
            module.fail_json(msg="The vrf parameter must be 'overlay-1' when tenant is 'infra' and mpls is 'yes'")
        child_classes += ["mplsExtP", "mplsRsLabelPol", "l3extProvLbl"]
        child_configs.append(
            dict(mplsExtP=dict(attributes=dict(), children=[dict(mplsRsLabelPol=dict(attributes=dict(tDn="uni/tn-infra/mplslabelpol-default")))]))
        )
        child_configs.append(dict(l3extProvLbl=dict(attributes=dict(name=l3out))))

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="l3extOut",
            aci_rn="out-{0}".format(l3out),
            module_object=l3out,
            target_filter={"name": l3out},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        if l3protocol is not None:
            if isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("l3extOut", {}).get("children", {}):
                    if child.get("bgpExtP") and "bgp" not in l3protocol:
                        child_configs.append(dict(bgpExtP=dict(attributes=dict(status="deleted"))))
                    if child.get("eigrpExtP") and "eigrp" not in l3protocol:
                        child_configs.append(dict(eigrpExtP=dict(attributes=dict(status="deleted"))))
                    if child.get("ospfExtP") and "ospf" not in l3protocol:
                        child_configs.append(dict(ospfExtP=dict(attributes=dict(status="deleted"))))
                    if child.get("pimExtP") and "pim" not in l3protocol:
                        child_configs.append(dict(pimExtP=dict(attributes=dict(status="deleted"))))

            for protocol in l3protocol:
                if protocol == "bgp":
                    child_configs.append(dict(bgpExtP=dict(attributes=dict(descr=""))))
                elif protocol == "eigrp":
                    child_configs.append(dict(eigrpExtP=dict(attributes=dict(asn=asn))))
                elif protocol == "ospf":
                    if isinstance(ospf, dict):
                        ospf["area_ctrl"] = ",".join(ospf.get("area_ctrl"))
                        child_configs.append(
                            dict(
                                ospfExtP=dict(
                                    attributes=dict(
                                        areaCost=ospf.get("area_cost"),
                                        areaCtrl=ospf.get("area_ctrl"),
                                        areaId=ospf.get("area_id"),
                                        areaType=ospf.get("area_type"),
                                        descr=ospf.get("description"),
                                        multipodInternal=ospf.get("multipod_internal"),
                                        nameAlias=ospf.get("name_alias"),
                                    )
                                )
                            )
                        )
                    else:
                        child_configs.append(dict(ospfExtP=dict(attributes=dict(descr=""))))
                elif protocol == "pim":
                    child_configs.append(dict(pimExtP=dict(attributes=dict(descr=""))))

        aci.payload(
            aci_class="l3extOut",
            class_config=dict(
                name=l3out,
                descr=description,
                enforceRtctrl=enforce_ctrl,
                mplsEnabled=mpls,
                targetDscp=dscp,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="l3extOut")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
