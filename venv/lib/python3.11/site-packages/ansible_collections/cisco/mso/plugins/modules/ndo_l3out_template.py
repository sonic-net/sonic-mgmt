#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_template
short_description: Manage L3Outs on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Outs on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the L3Out template.
    type: str
    aliases: [ l3out_template ]
    required: true
  name:
    description:
    - The name of the L3Out.
    type: str
  uuid:
    description:
    - The UUID of the L3Out.
    - This parameter is required when the L3Out O(name) needs to be updated.
    type: str
  description:
    description:
    - The description of the L3Out.
    - Providing an empty string will remove the O(description="") from the L3Out.
    type: str
  vrf:
    description:
    - The VRF associated with the L3Out.
    type: dict
    suboptions:
      name:
        description:
        - The name of the VRF.
        required: true
        type: str
      schema:
        description:
        - The name of the schema.
        required: true
        type: str
      template:
        description:
        - The name of the template.
        required: true
        type: str
  l3_domain:
    description:
    - The name of the L3 Domain.
    type: str
  target_dscp:
    description:
    - The DSCP Level of the L3Out.
    type: str
    choices:
      - af11
      - af12
      - af13
      - af21
      - af22
      - af23
      - af31
      - af32
      - af33
      - af41
      - af42
      - af43
      - cs0
      - cs1
      - cs2
      - cs3
      - cs4
      - cs5
      - cs6
      - cs7
      - expedited_forwarding
      - unspecified
      - voice_admit
  pim:
    description:
    - The protocol independent multicast (PIM) flag of the L3Out.
    - By default, PIM is disabled. To enable the PIM, Layer 3 Multicast must be enabled on the O(vrf).
    type: bool
  interleak:
    description:
    - The name of the Route Map Policy for Route Control that needs to be associated with Interleak route map.
    - Providing an empty string will remove the O(interleak="") from the L3Out.
    type: str
  static_route_redistribution:
    description:
    - The name of the Route Map Policy for Route Control that needs to be associated with Static Route Redistribution route map.
    - Providing an empty string will remove the O(static_route_redistribution="") from the L3Out.
    type: str
    aliases: [ static_route ]
  connected_route_redistribution:
    description:
    - The name of the Route Map Policy for Route Control that needs to be associated with Connected Route Redistribution route map.
    - Providing an empty string will remove the O(connected_route_redistribution="") from the L3Out.
    type: str
    aliases: [ connected_route ]
  attached_host_route_redistribution:
    description:
    - The name of the Route Map Policy for Route Control that needs to be associated with Attached Host Route Redistribution route map.
    - Providing an empty string will remove the O(attached_host_route_redistribution="") from the L3Out.
    type: str
    aliases: [ attached_host_route ]
  bgp:
    description:
    - The BGP routing protocol configuration of the L3Out.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the BGP routing protocol.
        - Use C(disabled) to remove the BGP routing protocol.
        type: str
        default: enabled
        choices: [enabled, disabled]
      inbound_route_map:
        description:
        - The name of the Route Map Policy for Route Control that needs to be associated with inbound route map.
        - Providing an empty string will remove the O(bgp.inbound_route_map="") from the L3Out.
        type: str
        aliases: [ import_route, inbound_route ]
      outbound_route_map:
        description:
        - The name of the Route Map Policy for Route Control that needs to be associated with outbound route map.
        - Providing an empty string will remove the O(bgp.outbound_route_map="") from the L3Out.
        type: str
        aliases: [ export_route, outbound_route ]
      route_dampening_ipv4:
        description:
        - The name of the Route Map Policy for Route Control that needs to be associated with Route Dampening IPv4 route map.
        - Providing an empty string will remove the O(bgp.route_dampening_ipv4="") from the L3Out.
        type: str
        aliases: [ dampening_ipv4 ]
      route_dampening_ipv6:
        description:
        - The name of the Route Map Policy for Route Control that needs to be associated with Route Dampening IPv6 route map.
        - Providing an empty string will remove the O(bgp.route_dampening_ipv6="") from the L3Out.
        type: str
        aliases: [ dampening_ipv6 ]
  ospf:
    description:
    - The OSPF routing protocol configuration of the L3Out.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the OSPF routing protocol.
        - Use C(disabled) to remove the OSPF routing protocol.
        type: str
        default: enabled
        choices: [enabled, disabled]
      area_id:
        description:
        - The area id of the OSPF area.
        - This option is required when the O(ospf.state=enabled).
        type: str
      area_type:
        description:
        - The area type of the OSPF area.
        - This option is required when the O(ospf.state=enabled).
        type: str
        choices: [regular, stub, nssa]
      cost:
        description:
        - The cost of the OSPF area.
        - Defaults to 1 when unset during creation.
        type: int
      originate_summary_lsa:
        description:
        - This option is for OSPF NSSA (not-so-stubby area) or Stub area.
        - When this option is disabled, not only Type 4 and 5, but also Type 3 LSAs are not sent into the NSSA or Stub area by the border leaf.
        - Instead, the border leaf creates and sends a default route to the area.
        - If there is no Type 3 LSA in this area in the first place, a default route is not created.
        type: bool
        aliases: [ originate_lsa ]
      send_redistributed_lsas:
        description:
        - This option is for the OSPF NSSA (not-so-stubby area).
        - When this option is disabled, the redistributed routes are not sent into this NSSA area from the border leaf.
        - This is typically used when the O(ospf.originate_summary_lsa=false).
        - Because disabling the O(ospf.originate_summary_lsa) option creates and sends a default route to the NSSA or Stub area.
        type: bool
        aliases: [ redistributed_lsas ]
      suppress_forwarding_addr_translated_lsa:
        description:
        - This option is for OSPF NSSA (not-so-stubby area).
        - When an OSPF NSSA ABR (Area Border Router) translates a Type-7 LSA into a Type-5 LSA to send it across non-NSSA areas.
        - It typically includes the IP address of the originator ASBR (Autonomous System Boundary Router) as a forwarding address.
        - However, if an OSPF router receiving the Type-5 LSA lacks a route to this forwarding address.
        - The route may not be installed in the router's route table.
        - Enabling this option prevents the ABR from adding a forwarding address during the Type-7 to Type-5 translation, thereby avoiding this issue.
        type: bool
        aliases: [ suppress_fa_lsa ]
      originate_default_route:
        description:
        - The Originate Default Route option in an L3Out configuration allows the ACI fabric to advertise a default route (0.0.0.0/0) to external networks.
        - Providing an empty string will remove the O(ospf.originate_default_route) from the L3Out.
        type: str
        choices: [ only, in_addition, "" ]
      originate_default_route_always:
        description:
        - Enabling this option will set the O(ospf.originate_default_route=only) when the O(ospf.originate_default_route) unset during creation.
        - This option is applicable only if OSPF is configured on the L3Out.
        type: bool
        aliases: [ always ]
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the L3Out template.
- The O(vrf) must exist before using this module in your playbook.
  Use M(cisco.mso.mso_schema_template_vrf) to create the VRF.
- The O(l3_domain) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_l3_domain) to create the L3Out domain.
seealso:
- module: cisco.mso.mso_schema_template_vrf
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_l3_domain
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new L3Out object without BGP and OSPF
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    name: "l3out_1"
    vrf:
      name: "VRF1"
      schema: "Schema1"
      template: "Template1"
    state: "present"

- name: Query a L3Out object with name
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    name: "l3out_1"
    state: "query"
  register: query_l3out_name

- name: Update a L3Out object name with UUID
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    uuid: "{{ query_l3out_name.current.uuid }}"
    name: "l3out_1_updated"
    description: "updated description"
    state: "present"

- name: Create a new L3Out object with BGP and OSPF
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    name: "l3out_1_new"
    vrf:
      name: "VRF1"
      schema: "Schema1"
      template: "Template1"
    routing_protocols: ["bgp", "ospf"]
    bgp:
      inbound_route_map: "ans_route_map"
      outbound_route_map: "ans_route_map"
      route_dampening_ipv4: "ans_route_map"
      route_dampening_ipv6: "ans_route_map"
    ospf:
      area_id: "0.0.0.1"
      area_type: "regular"
      cost: 1
      send_redistributed_lsas: true
      originate_summary_lsa: true
      suppress_forwarding_addr_translated_lsa: true
      originate_default_route: "only"
      originate_default_route_always: false
    interleak: "ans_route_map"
    static_route_redistribution: "ans_route_map"
    connected_route_redistribution: "ans_route_map"
    attached_host_route_redistribution: "ans_route_map"
    state: "present"

- name: Update a L3Out object BGP and OSPF values
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    name: "l3out_1_new"
    vrf:
      name: "VRF1"
      schema: "Schema1"
      template: "Template1"
    routing_protocols: ["bgp", "ospf"]
    bgp:
      route_dampening_ipv4: "ans_route_map_2"
      route_dampening_ipv6: "ans_route_map_2"
    ospf:
      area_id: "0.0.0.2"
      area_type: "stub"
      cost: 3
      send_redistributed_lsas: true
      originate_summary_lsa: true
      suppress_forwarding_addr_translated_lsa: true
    interleak: "ans_route_map"
    static_route_redistribution: "ans_route_map"
    connected_route_redistribution: "ans_route_map"
    attached_host_route_redistribution: "ans_route_map"
    state: "present"

- name: Clear bgp and ospf routing protocol from the existing L3Out
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    name: "l3out_1_new"
    vrf:
      name: "VRF1"
      schema: "Schema1"
      template: "Template1"
    routing_protocol: ["bgp"]
    bgp:
      state: disabled
    ospf:
      state: disabled
    state: "present"

- name: Query a L3Out object with uuid
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    uuid: "{{ query_l3out_name.current.uuid }}"
    state: "query"
  register: query_l3out_name

- name: Query all L3Out objects
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    state: "query"
  register: query_all_l3out

- name: Delete a L3Out object with name
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    name: "l3out_1"
    state: "absent"

- name: Delete a L3Out object with uuid
  cisco.mso.ndo_l3out_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    l3out_template: l3out_template
    uuid: "{{ query_l3out_name.current.uuid }}"
    state: "absent"
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import TARGET_DSCP_MAP, ORIGINATE_DEFAULT_ROUTE, L3OUT_ROUTING_PROTOCOLS
from ansible_collections.cisco.mso.plugins.module_utils.utils import generate_api_endpoint


def get_routing_protocol(existing_protocol, ospf_state, bgp_state):
    protocols = set()

    if bgp_state == "enabled" or (bgp_state == "ignore" and "bgp" in L3OUT_ROUTING_PROTOCOLS.get(existing_protocol)):
        protocols.add("bgp")

    if ospf_state == "enabled" or (ospf_state == "ignore" and "ospf" in L3OUT_ROUTING_PROTOCOLS.get(existing_protocol)):
        protocols.add("ospf")

    return "".join(protocols) if len(protocols) < 2 else L3OUT_ROUTING_PROTOCOLS.get("".join(protocols))


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True, aliases=["l3out_template"]),
        name=dict(type="str"),
        uuid=dict(type="str"),
        description=dict(type="str"),
        vrf=dict(
            type="dict",
            options=dict(
                name=dict(type="str", required=True),
                schema=dict(type="str", required=True),
                template=dict(type="str", required=True),
            ),
        ),
        l3_domain=dict(type="str"),
        target_dscp=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        pim=dict(type="bool"),
        interleak=dict(type="str"),
        static_route_redistribution=dict(type="str", aliases=["static_route"]),
        connected_route_redistribution=dict(type="str", aliases=["connected_route"]),
        attached_host_route_redistribution=dict(type="str", aliases=["attached_host_route"]),
        ospf=dict(
            type="dict",
            options=dict(
                state=dict(type="str", choices=["enabled", "disabled"], default="enabled"),
                area_id=dict(type="str"),
                area_type=dict(type="str", choices=["regular", "stub", "nssa"]),
                cost=dict(type="int"),
                send_redistributed_lsas=dict(type="bool", aliases=["redistributed_lsas"]),
                originate_summary_lsa=dict(type="bool", aliases=["originate_lsa"]),
                suppress_forwarding_addr_translated_lsa=dict(type="bool", aliases=["suppress_fa_lsa"]),
                originate_default_route=dict(type="str", choices=list(ORIGINATE_DEFAULT_ROUTE)),
                originate_default_route_always=dict(type="bool", aliases=["always"]),
            ),
            required_if=[
                ["state", "enabled", ["area_id", "area_type"]],
            ],
        ),
        bgp=dict(
            type="dict",
            options=dict(
                state=dict(type="str", choices=["enabled", "disabled"], default="enabled"),
                inbound_route_map=dict(type="str", aliases=["import_route", "inbound_route"]),
                outbound_route_map=dict(type="str", aliases=["export_route", "outbound_route"]),
                route_dampening_ipv4=dict(type="str", aliases=["dampening_ipv4"]),
                route_dampening_ipv6=dict(type="str", aliases=["dampening_ipv6"]),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
    )

    mso = MSOModule(module)

    l3out_template = module.params.get("l3out_template")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    l3_domain = module.params.get("l3_domain")
    pim = module.params.get("pim")
    interleak = module.params.get("interleak")
    static_route_redistribution = module.params.get("static_route_redistribution")
    connected_route_redistribution = module.params.get("connected_route_redistribution")
    attached_host_route_redistribution = module.params.get("attached_host_route_redistribution")
    target_dscp = TARGET_DSCP_MAP.get(module.params.get("target_dscp"))
    vrf_dict = module.params.get("vrf") if module.params.get("vrf") else {}
    ospf = module.params.get("ospf")
    bgp = module.params.get("bgp")

    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "l3out", l3out_template)
    mso_template.validate_template("l3out")

    tenant_id = mso_template.template_summary.get("tenantId")
    tenant_name = mso_template.template_summary.get("tenantName")

    match = mso_template.get_l3out_object(uuid, name)

    if (uuid or name) and match:
        mso.existing = mso.previous = copy.deepcopy(insert_l3out_relation_name(match.details, mso_template))  # Query a specific object
    elif match:
        mso.existing = [insert_l3out_relation_name(l3out, mso_template) for l3out in match]  # Query all objects

    if state != "query":
        path = "/l3outTemplate/l3outs/{0}".format(match.index if match else "-")

    ops = []

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="L3Out with the uuid: '{0}' not found".format(uuid))

        templates_objects_path = "templates/objects"
        route_map_params = {"type": "routeMap", "tenant-id": tenant_id}
        route_map_path = generate_api_endpoint(templates_objects_path, **route_map_params)
        route_map_objects = mso.query_objs(route_map_path)

        vrf_ref = None
        if vrf_dict:
            vrf_object = mso_template.get_vrf_object(vrf_dict, tenant_id, templates_objects_path)
            if pim and vrf_object.details.get("l3MCast") is False:
                mso.fail_json(
                    msg="Invalid configuration in L3Out {0}, 'PIM' cannot be enabled while using the VRF '{1}' with L3 Multicast disabled".format(
                        "UUID: {0}".format(uuid) if uuid else "Name: {0}".format(name), vrf_dict.get("name")
                    )
                )
            vrf_ref = vrf_object.details.get("uuid")

        existing_routing_protocols = mso.existing.get("routingProtocol", None)

        ospf_state = ospf.get("state") if ospf else "ignore"
        bgp_state = bgp.get("state") if bgp else "ignore"

        res_routing_protocols = get_routing_protocol(None if existing_routing_protocols == "none" else existing_routing_protocols, ospf_state, bgp_state)

        routing_protocols = res_routing_protocols if res_routing_protocols else "none"

        if not mso.existing:
            payload = dict(name=name)

            payload["routingProtocol"] = routing_protocols

            if vrf_ref is None:
                mso.fail_json(msg="The O(vrf) is required during the creation.")

            payload["vrfRef"] = vrf_ref
            payload["vrfName"] = vrf_dict.get("name")

            if description:
                payload["description"] = description

            if l3_domain:
                payload["l3domain"] = l3_domain

            if target_dscp:
                payload["targetDscp"] = target_dscp

            if pim is not None:
                payload["pim"] = pim

            outer_route_maps = dict()
            if interleak:
                outer_route_maps["interleakName"] = interleak
                outer_route_maps["interleakRef"] = mso_template.get_route_map(
                    "interleak",
                    tenant_id,
                    tenant_name,
                    interleak,
                    route_map_objects,
                ).get("uuid", "")

            if static_route_redistribution:
                outer_route_maps["staticRouteRedistName"] = static_route_redistribution
                outer_route_maps["staticRouteRedistRef"] = mso_template.get_route_map(
                    "static_route_redistribution",
                    tenant_id,
                    tenant_name,
                    static_route_redistribution,
                    route_map_objects,
                ).get("uuid", "")

            if connected_route_redistribution:
                outer_route_maps["connectedRouteRedistName"] = connected_route_redistribution
                outer_route_maps["connectedRouteRedistRef"] = mso_template.get_route_map(
                    "connected_route_redistribution",
                    tenant_id,
                    tenant_name,
                    connected_route_redistribution,
                    route_map_objects,
                ).get("uuid", "")

            if attached_host_route_redistribution:
                outer_route_maps["attachedHostRouteRedistName"] = attached_host_route_redistribution
                outer_route_maps["attachedHostRouteRedistRef"] = mso_template.get_route_map(
                    "attached_host_route_redistribution",
                    tenant_id,
                    tenant_name,
                    attached_host_route_redistribution,
                    route_map_objects,
                ).get("uuid", "")

            if outer_route_maps:
                payload["advancedRouteMapRefs"] = outer_route_maps

            if bgp:
                if bgp.get("inbound_route_map"):
                    payload["importRouteMapName"] = bgp.get("inbound_route_map")
                    payload["importRouteMapRef"] = mso_template.get_route_map(
                        "inbound_route_map",
                        tenant_id,
                        tenant_name,
                        bgp.get("inbound_route_map"),
                        route_map_objects,
                    ).get("uuid", "")

                payload["importRouteControl"] = True if payload.get("importRouteMapRef") else False

                if bgp.get("outbound_route_map"):
                    payload["exportRouteMapName"] = bgp.get("outbound_route_map")
                    payload["exportRouteMapRef"] = mso_template.get_route_map(
                        "outbound_route_map",
                        tenant_id,
                        tenant_name,
                        bgp.get("outbound_route_map"),
                        route_map_objects,
                    ).get("uuid", "")

                if bgp.get("route_dampening_ipv4"):
                    payload["advancedRouteMapRefs"]["routeDampeningV4Name"] = bgp.get("route_dampening_ipv4")
                    payload["advancedRouteMapRefs"]["routeDampeningV4Ref"] = mso_template.get_route_map(
                        "route_dampening_ipv4",
                        tenant_id,
                        tenant_name,
                        bgp.get("route_dampening_ipv4"),
                        route_map_objects,
                    ).get("uuid", "")

                if bgp.get("route_dampening_ipv6"):
                    payload["advancedRouteMapRefs"]["routeDampeningV6Name"] = bgp.get("route_dampening_ipv6")
                    payload["advancedRouteMapRefs"]["routeDampeningV6Ref"] = mso_template.get_route_map(
                        "route_dampening_ipv6",
                        tenant_id,
                        tenant_name,
                        bgp.get("route_dampening_ipv6"),
                        route_map_objects,
                    ).get("uuid", "")

            if ospf:
                payload["ospfAreaConfig"] = dict(
                    cost=ospf.get("cost"),
                    id=ospf.get("area_id"),
                    areaType=ospf.get("area_type"),
                )

                default_route_leak = dict()
                if ospf.get("originate_default_route"):
                    default_route_leak["originateDefaultRoute"] = ORIGINATE_DEFAULT_ROUTE.get(ospf.get("originate_default_route"))

                if ospf.get("originate_default_route_always") is not None:
                    default_route_leak["always"] = ospf.get("originate_default_route_always")

                if default_route_leak:
                    payload["defaultRouteLeak"] = default_route_leak

                redistribute = ospf.get("send_redistributed_lsas")
                originate = ospf.get("originate_summary_lsa")
                suppress_fa = ospf.get("suppress_forwarding_addr_translated_lsa")

                control = dict()
                if redistribute is not None:
                    control["redistribute"] = redistribute

                if originate is not None:
                    control["originate"] = originate

                if suppress_fa is not None:
                    control["suppressFA"] = suppress_fa

                if control:
                    payload["ospfAreaConfig"]["control"] = control

            mso.sanitize(payload)
            ops.append(dict(op="add", path=path, value=payload))
        elif mso.existing:
            proposed_payload = copy.deepcopy(match.details)

            if name is not [None, ""] and mso.existing.get("name") != name:
                ops.append(dict(op="replace", path=path + "/name", value=name))
                proposed_payload["name"] = name

            if mso.existing.get("routingProtocol") != routing_protocols:
                ops.append(dict(op="replace", path=path + "/routingProtocol", value=routing_protocols))
                proposed_payload["routingProtocol"] = routing_protocols

            if vrf_ref is not None and mso.existing.get("vrfRef") != vrf_ref:
                ops.append(dict(op="replace", path=path + "/vrfRef", value=vrf_ref))
                proposed_payload["vrfRef"] = vrf_ref
                proposed_payload["vrfName"] = vrf_dict.get("name")

            if description is not None and mso.existing.get("description") != description:
                ops.append(dict(op="replace", path=path + "/description", value=description))
                proposed_payload["description"] = description

            if l3_domain is not None and mso.existing.get("l3domain") != l3_domain:
                ops.append(dict(op="replace", path=path + "/l3domain", value=l3_domain))
                proposed_payload["l3domain"] = l3_domain

            if target_dscp is not None and mso.existing.get("targetDscp") != target_dscp:
                ops.append(dict(op="replace", path=path + "/targetDscp", value=target_dscp))
                proposed_payload["targetDscp"] = target_dscp

            if pim is not None and mso.existing.get("pim") != pim:
                ops.append(dict(op="replace", path=path + "/pim", value=pim))
                proposed_payload["pim"] = pim

            if (
                interleak is not None
                or static_route_redistribution is not None
                or connected_route_redistribution is not None
                or attached_host_route_redistribution is not None
                or (bgp is not None and (bgp.get("route_dampening_ipv4") is not None or bgp.get("route_dampening_ipv6") is not None))
            ) and not mso.existing.get("advancedRouteMapRefs"):
                ops.append(dict(op="add", path=path + "/advancedRouteMapRefs", value=dict()))
                proposed_payload["advancedRouteMapRefs"] = dict()

            outer_route_maps = dict()

            if interleak is not None:
                interleak_ref = mso_template.get_route_map(
                    "interleak",
                    tenant_id,
                    tenant_name,
                    interleak,
                    route_map_objects,
                ).get("uuid", "")

                if mso.existing.get("advancedRouteMapRefs", {}).get("interleakRef") != interleak_ref:
                    ops.append(dict(op="replace", path=path + "/advancedRouteMapRefs/interleakRef", value=interleak_ref))
                    outer_route_maps["interleakRef"] = interleak_ref
                    outer_route_maps["interleakName"] = interleak

            if static_route_redistribution is not None:
                static_route_redistribution_ref = mso_template.get_route_map(
                    "static_route_redistribution",
                    tenant_id,
                    tenant_name,
                    static_route_redistribution,
                    route_map_objects,
                ).get("uuid", "")

                if mso.existing.get("advancedRouteMapRefs", {}).get("staticRouteRedistRef") != static_route_redistribution_ref:
                    ops.append(dict(op="replace", path=path + "/advancedRouteMapRefs/staticRouteRedistRef", value=static_route_redistribution_ref))
                    outer_route_maps["staticRouteRedistRef"] = static_route_redistribution_ref
                    outer_route_maps["staticRouteRedistName"] = static_route_redistribution

            if connected_route_redistribution is not None:
                connected_route_redistribution_ref = mso_template.get_route_map(
                    "connected_route_redistribution",
                    tenant_id,
                    tenant_name,
                    connected_route_redistribution,
                    route_map_objects,
                ).get("uuid", "")

                if mso.existing.get("advancedRouteMapRefs", {}).get("connectedRouteRedistRef") != connected_route_redistribution_ref:
                    ops.append(dict(op="replace", path=path + "/advancedRouteMapRefs/connectedRouteRedistRef", value=connected_route_redistribution_ref))
                    outer_route_maps["connectedRouteRedistRef"] = connected_route_redistribution_ref
                    outer_route_maps["connectedRouteRedistName"] = connected_route_redistribution

            if attached_host_route_redistribution is not None:
                attached_host_route_redistribution_ref = mso_template.get_route_map(
                    "attached_host_route_redistribution",
                    tenant_id,
                    tenant_name,
                    attached_host_route_redistribution,
                    route_map_objects,
                ).get("uuid", "")

                if mso.existing.get("advancedRouteMapRefs", {}).get("attachedHostRouteRedistRef") != attached_host_route_redistribution_ref:
                    ops.append(
                        dict(
                            op="replace",
                            path=path + "/advancedRouteMapRefs/attachedHostRouteRedistRef",
                            value=attached_host_route_redistribution_ref,
                        )
                    )
                    outer_route_maps["attachedHostRouteRedistRef"] = attached_host_route_redistribution_ref
                    outer_route_maps["attachedHostRouteRedistName"] = attached_host_route_redistribution

            if bgp and bgp_state != "disabled":
                if bgp.get("inbound_route_map") is not None:
                    inbound_route_map_ref = mso_template.get_route_map(
                        "inbound_route_map",
                        tenant_id,
                        tenant_name,
                        bgp.get("inbound_route_map"),
                        route_map_objects,
                    ).get("uuid", "")

                    if mso.existing.get("importRouteMapRef") != inbound_route_map_ref:
                        ops.append(dict(op="replace", path=path + "/importRouteMapRef", value=inbound_route_map_ref))
                        ops.append(dict(op="replace", path=path + "/importRouteControl", value=True if inbound_route_map_ref else False))

                        proposed_payload["importRouteMapRef"] = inbound_route_map_ref
                        proposed_payload["importRouteMapName"] = bgp.get("inbound_route_map")
                        proposed_payload["importRouteControl"] = True if inbound_route_map_ref else False

                if bgp.get("outbound_route_map") is not None:
                    outbound_route_map_ref = mso_template.get_route_map(
                        "outbound_route_map",
                        tenant_id,
                        tenant_name,
                        bgp.get("outbound_route_map"),
                        route_map_objects,
                    ).get("uuid", "")

                    if mso.existing.get("exportRouteMapRef") != outbound_route_map_ref:
                        ops.append(dict(op="replace", path=path + "/exportRouteMapRef", value=outbound_route_map_ref))
                        proposed_payload["exportRouteMapRef"] = outbound_route_map_ref
                        proposed_payload["exportRouteMapName"] = bgp.get("outbound_route_map")

                if bgp.get("route_dampening_ipv4") is not None:
                    route_dampening_ipv4_ref = mso_template.get_route_map(
                        "route_dampening_ipv4",
                        tenant_id,
                        tenant_name,
                        bgp.get("route_dampening_ipv4"),
                        route_map_objects,
                    ).get("uuid", "")

                    if mso.existing.get("advancedRouteMapRefs", {}).get("routeDampeningV4Ref") != route_dampening_ipv4_ref:
                        ops.append(dict(op="replace", path=path + "/advancedRouteMapRefs/routeDampeningV4Ref", value=route_dampening_ipv4_ref))
                        outer_route_maps["routeDampeningV4Ref"] = route_dampening_ipv4_ref
                        outer_route_maps["routeDampeningV4Name"] = bgp.get("route_dampening_ipv4")

                if bgp.get("route_dampening_ipv6") is not None:
                    route_dampening_ipv6_ref = mso_template.get_route_map(
                        "route_dampening_ipv6",
                        tenant_id,
                        tenant_name,
                        bgp.get("route_dampening_ipv6"),
                        route_map_objects,
                    ).get("uuid", "")

                    if mso.existing.get("advancedRouteMapRefs", {}).get("routeDampeningV6Ref") != route_dampening_ipv6_ref:
                        ops.append(dict(op="replace", path=path + "/advancedRouteMapRefs/routeDampeningV6Ref", value=route_dampening_ipv6_ref))
                        outer_route_maps["routeDampeningV6Ref"] = route_dampening_ipv6_ref
                        outer_route_maps["routeDampeningV6Name"] = bgp.get("route_dampening_ipv6")

            elif bgp_state == "disabled":
                ops.append(dict(op="replace", path=path + "/importRouteMapRef", value=""))
                ops.append(dict(op="replace", path=path + "/importRouteControl", value=False))
                proposed_payload.pop("importRouteMapRef", None)
                proposed_payload["importRouteControl"] = False

                ops.append(dict(op="replace", path=path + "/exportRouteMapRef", value=""))
                proposed_payload.pop("exportRouteMapRef", None)

                ops.append(dict(op="replace", path=path + "/advancedRouteMapRefs/routeDampeningV6Ref", value=""))
                proposed_payload.get("advancedRouteMapRefs", {}).pop("routeDampeningV6Ref", None)

                ops.append(dict(op="replace", path=path + "/advancedRouteMapRefs/routeDampeningV4Ref", value=""))
                proposed_payload.get("advancedRouteMapRefs", {}).pop("routeDampeningV4Ref", None)

            if outer_route_maps:
                for key, value in outer_route_maps.items():
                    proposed_payload["advancedRouteMapRefs"][key] = value

            if ospf and ospf_state != "disabled":
                originate_default_route = ORIGINATE_DEFAULT_ROUTE.get(ospf.get("originate_default_route"))
                originate_default_route_always = ospf.get("originate_default_route_always")

                if originate_default_route is not None and originate_default_route == "" and mso.existing.get("defaultRouteLeak"):
                    ops.append(dict(op="remove", path=path + "/defaultRouteLeak"))
                    proposed_payload.pop("defaultRouteLeak", None)

                elif (originate_default_route is not None and originate_default_route != "") or (originate_default_route_always is not None):
                    if not mso.existing.get("defaultRouteLeak"):
                        ops.append(dict(op="replace", path=path + "/defaultRouteLeak", value=dict()))
                        proposed_payload["defaultRouteLeak"] = dict()

                    if originate_default_route != mso.existing.get("defaultRouteLeak", {}).get("originateDefaultRoute"):
                        ops.append(
                            dict(
                                op="replace",
                                path=path + "/defaultRouteLeak/originateDefaultRoute",
                                value=originate_default_route,
                            )
                        )
                        proposed_payload["defaultRouteLeak"]["originateDefaultRoute"] = originate_default_route

                    if originate_default_route_always is not None and originate_default_route_always != mso.existing.get("defaultRouteLeak", {}).get("always"):
                        ops.append(dict(op="replace", path=path + "/defaultRouteLeak/always", value=originate_default_route_always))
                        proposed_payload["defaultRouteLeak"]["always"] = originate_default_route_always

                if not mso.existing.get("ospfAreaConfig"):
                    ops.append(dict(op="replace", path=path + "/ospfAreaConfig", value=dict()))
                    proposed_payload["ospfAreaConfig"] = dict()

                if ospf.get("cost") is not None and ospf.get("cost") != mso.existing.get("ospfAreaConfig", {}).get("cost"):
                    ops.append(dict(op="replace", path=path + "/ospfAreaConfig/cost", value=ospf.get("cost")))
                    proposed_payload["ospfAreaConfig"]["cost"] = ospf.get("cost")

                if ospf.get("area_id") is not None and ospf.get("area_id") != mso.existing.get("ospfAreaConfig", {}).get("id"):
                    ops.append(dict(op="replace", path=path + "/ospfAreaConfig/id", value=ospf.get("area_id")))
                    proposed_payload["ospfAreaConfig"]["id"] = ospf.get("area_id")

                if ospf.get("area_type") is not None and ospf.get("area_type") != mso.existing.get("ospfAreaConfig", {}).get("areaType"):
                    ops.append(dict(op="replace", path=path + "/ospfAreaConfig/areaType", value=ospf.get("area_type")))
                    proposed_payload["ospfAreaConfig"]["areaType"] = ospf.get("area_type")

                redistribute = ospf.get("send_redistributed_lsas")
                originate = ospf.get("originate_summary_lsa")
                suppress_fa = ospf.get("suppress_forwarding_addr_translated_lsa")

                if (redistribute is not None or originate is not None or suppress_fa is not None) and not mso.existing.get("ospfAreaConfig", {}).get(
                    "control"
                ):
                    ops.append(dict(op="replace", path=path + "/ospfAreaConfig/control", value=dict()))
                    proposed_payload["ospfAreaConfig"]["control"] = dict()

                if redistribute is not None and redistribute != mso.existing.get("ospfAreaConfig", {}).get("control", {}).get("redistribute"):
                    ops.append(dict(op="replace", path=path + "/ospfAreaConfig/control/redistribute", value=redistribute))
                    proposed_payload["ospfAreaConfig"]["control"]["redistribute"] = redistribute

                if originate is not None and originate != mso.existing.get("ospfAreaConfig", {}).get("control", {}).get("originate"):
                    ops.append(dict(op="replace", path=path + "/ospfAreaConfig/control/originate", value=originate))
                    proposed_payload["ospfAreaConfig"]["control"]["originate"] = originate

                if suppress_fa is not None and suppress_fa != mso.existing.get("ospfAreaConfig", {}).get("control", {}).get("suppressFA"):
                    ops.append(dict(op="replace", path=path + "/ospfAreaConfig/control/suppressFA", value=suppress_fa))
                    proposed_payload["ospfAreaConfig"]["control"]["suppressFA"] = suppress_fa

            elif ospf_state == "disabled":
                ops.append(dict(op="remove", path=path + "/ospfAreaConfig"))
                proposed_payload.pop("ospfAreaConfig", None)

                ops.append(dict(op="remove", path=path + "/defaultRouteLeak"))
                proposed_payload.pop("defaultRouteLeak", None)

            mso.sanitize(proposed_payload, collate=True)

    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path="/l3outTemplate/l3outs/{0}".format(match.index)))

    if not module.check_mode and ops:
        response_object = mso.request(mso_template.template_path, method="PATCH", data=ops)

        mso_template.template = response_object
        match = mso_template.get_l3out_object(uuid, name)

        if match:
            mso.existing = insert_l3out_relation_name(match.details, mso_template)  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = insert_l3out_relation_name(mso.proposed, mso_template, module.check_mode) if state == "present" else {}

    mso.exit_json()


def insert_l3out_relation_name(l3out_object, mso_template, check_mode=False):
    l3out_object["vrfName"] = mso_template.get_template_object_name_by_uuid("vrf", l3out_object.get("vrfRef"))

    if not check_mode:
        l3out_relations = mso_template.mso.request("{0}/relations".format(mso_template.template_path), "GET")
        route_map_policies = l3out_relations.get("relations", {}).get("identities", {}).get("routeMapPolicies", [])

    if "exportRouteMapRef" in l3out_object:
        if check_mode:
            l3out_object["exportRouteMapName"] = mso_template.get_template_object_name_by_uuid("routeMap", l3out_object["exportRouteMapRef"])
        else:
            l3out_object["exportRouteMapName"] = (
                mso_template.get_object_by_key_value_pairs(
                    "Route Map",
                    route_map_policies,
                    [KVPair("ref", l3out_object["exportRouteMapRef"])],
                    True,
                ).details
                or {}
            ).get("displayName")

    if "importRouteMapRef" in l3out_object:
        if check_mode:
            l3out_object["importRouteMapName"] = mso_template.get_template_object_name_by_uuid("routeMap", l3out_object["importRouteMapRef"])
        else:
            l3out_object["importRouteMapName"] = (
                mso_template.get_object_by_key_value_pairs(
                    "Route Map",
                    route_map_policies,
                    [KVPair("ref", l3out_object["importRouteMapRef"])],
                    True,
                ).details
                or {}
            ).get("displayName")

    advanced_route_maps = l3out_object.get("advancedRouteMapRefs")
    if advanced_route_maps is not None:
        if "attachedHostRouteRedistRef" in advanced_route_maps:
            if check_mode:
                l3out_object["advancedRouteMapRefs"]["attachedHostRouteRedistName"] = mso_template.get_template_object_name_by_uuid(
                    "routeMap", advanced_route_maps["attachedHostRouteRedistRef"]
                )
            else:
                l3out_object["advancedRouteMapRefs"]["attachedHostRouteRedistName"] = (
                    mso_template.get_object_by_key_value_pairs(
                        "Route Map",
                        route_map_policies,
                        [KVPair("ref", advanced_route_maps["attachedHostRouteRedistRef"])],
                        True,
                    ).details
                    or {}
                ).get("displayName")

        if "connectedRouteRedistRef" in advanced_route_maps:
            if check_mode:
                l3out_object["advancedRouteMapRefs"]["connectedRouteRedistName"] = mso_template.get_template_object_name_by_uuid(
                    "routeMap", advanced_route_maps["connectedRouteRedistRef"]
                )
            else:
                l3out_object["advancedRouteMapRefs"]["connectedRouteRedistName"] = (
                    mso_template.get_object_by_key_value_pairs(
                        "Route Map",
                        route_map_policies,
                        [KVPair("ref", advanced_route_maps["connectedRouteRedistRef"])],
                        True,
                    ).details
                    or {}
                ).get("displayName")

        if "interleakRef" in advanced_route_maps:
            if check_mode:
                l3out_object["advancedRouteMapRefs"]["interleakName"] = mso_template.get_template_object_name_by_uuid(
                    "routeMap", advanced_route_maps["interleakRef"]
                )
            else:
                l3out_object["advancedRouteMapRefs"]["interleakName"] = (
                    mso_template.get_object_by_key_value_pairs(
                        "Route Map",
                        route_map_policies,
                        [KVPair("ref", advanced_route_maps["interleakRef"])],
                        True,
                    ).details
                    or {}
                ).get("displayName")

        if "routeDampeningV4Ref" in advanced_route_maps:
            if check_mode:
                l3out_object["advancedRouteMapRefs"]["routeDampeningV4Name"] = mso_template.get_template_object_name_by_uuid(
                    "routeMap", advanced_route_maps["routeDampeningV4Ref"]
                )
            else:
                l3out_object["advancedRouteMapRefs"]["routeDampeningV4Name"] = (
                    mso_template.get_object_by_key_value_pairs(
                        "Route Map",
                        route_map_policies,
                        [KVPair("ref", advanced_route_maps["routeDampeningV4Ref"])],
                        True,
                    ).details
                    or {}
                ).get("displayName")

        if "routeDampeningV6Ref" in advanced_route_maps:
            if check_mode:
                l3out_object["advancedRouteMapRefs"]["routeDampeningV6Name"] = mso_template.get_template_object_name_by_uuid(
                    "routeMap", advanced_route_maps["routeDampeningV6Ref"]
                )
            else:
                l3out_object["advancedRouteMapRefs"]["routeDampeningV6Name"] = (
                    mso_template.get_object_by_key_value_pairs(
                        "Route Map",
                        route_map_policies,
                        [KVPair("ref", advanced_route_maps["routeDampeningV6Ref"])],
                        True,
                    ).details
                    or {}
                ).get("displayName")

        if "staticRouteRedistRef" in advanced_route_maps:
            if check_mode:
                l3out_object["advancedRouteMapRefs"]["staticRouteRedistName"] = mso_template.get_template_object_name_by_uuid(
                    "routeMap", advanced_route_maps["staticRouteRedistRef"]
                )
            else:
                l3out_object["advancedRouteMapRefs"]["staticRouteRedistName"] = (
                    mso_template.get_object_by_key_value_pairs(
                        "Route Map",
                        route_map_policies,
                        [KVPair("ref", advanced_route_maps["staticRouteRedistRef"])],
                        True,
                    ).details
                    or {}
                ).get("displayName")
    return l3out_object


if __name__ == "__main__":
    main()
