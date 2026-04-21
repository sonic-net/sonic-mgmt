#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Jacob McGill (@jmcgill298)
# Copyright: (c) 2024, Samita Bhattacharjee (@samitab) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_bd
short_description: Manage Bridge Domains (BD) objects (fv:BD)
description:
- Manages Bridge Domains (BD) on Cisco ACI fabrics.
options:
  arp_flooding:
    description:
    - Determines if the Bridge Domain should flood ARP traffic.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  bd:
    description:
    - The name of the Bridge Domain.
    type: str
    aliases: [ bd_name, name ]
  bd_type:
    description:
    - The type of traffic on the Bridge Domain.
    - The APIC defaults to C(ethernet) when unset during creation.
    type: str
    choices: [ ethernet, fc ]
  description:
    description:
    - Description for the Bridge Domain.
    type: str
  enable_multicast:
    description:
    - Determines if PIM is enabled.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  enable_routing:
    description:
    - Determines if IP forwarding should be allowed.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  endpoint_clear:
    description:
    - Clears all End Points in all Leaves when C(true).
    - The value is not reset to disabled once End Points have been cleared; that requires a second task.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  endpoint_move_detect:
    description:
    - Determines if GARP should be enabled to detect when End Points move.
    type: str
    choices: [ default, garp ]
  endpoint_retention_action:
    description:
    - Determines if the Bridge Domain should inherit or resolve the End Point Retention Policy.
    - The APIC defaults to C(resolve) when unset during creation.
    type: str
    choices: [ inherit, resolve ]
  endpoint_retention_policy:
    description:
    - The name of the End Point Retention Policy the Bridge Domain should use when
      overriding the default End Point Retention Policy.
    type: str
  igmp_snoop_policy:
    description:
    - The name of the IGMP Snooping Policy the Bridge Domain should use when
      overriding the default IGMP Snooping Policy.
    type: str
  ip_learning:
    description:
    - Determines if the Bridge Domain should learn End Point IPs.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  ipv6_nd_policy:
    description:
    - The name of the IPv6 Neighbor Discovery Policy the Bridge Domain should use when
      overridding the default IPV6 ND Policy.
    type: str
  l2_unknown_unicast:
    description:
    - Determines what forwarding method to use for unknown l2 destinations.
    - The APIC defaults to C(proxy) when unset during creation.
    type: str
    choices: [ proxy, flood ]
  l3_unknown_multicast:
    description:
    - Determines the forwarding method to use for unknown multicast destinations.
    - The APIC defaults to C(flood) when unset during creation.
    type: str
    choices: [ flood, opt-flood ]
  ipv6_l3_unknown_multicast:
    description:
    - Determines the forwarding method to use for IPv6 unknown multicast destinations.
    - The APIC defaults to C(flood) when unset during creation.
    type: str
    choices: [ flood, opt-flood ]
  limit_ip_learn:
    description:
    - Determines if the BD should limit IP learning to only subnets owned by the Bridge Domain.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  mac_address:
    description:
    - The MAC Address to assign to the C(bd) instead of using the default.
    - The APIC defaults to C(00:22:BD:F8:19:FF) when unset during creation.
    type: str
    aliases: [ mac ]
  multi_dest:
    description:
    - Determines the forwarding method for L2 multicast, broadcast, and link layer traffic.
    - The APIC defaults to C(bd-flood) when unset during creation.
    type: str
    choices: [ bd-flood, drop, encap-flood ]
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
  tenant:
    description:
    - The name of the Tenant.
    type: str
    aliases: [ tenant_name ]
  vrf:
    description:
    - The name of the VRF.
    type: str
    aliases: [ vrf_name ]
  route_profile:
    description:
    - The Route Profile to associate with the Bridge Domain.
    type: str
  route_profile_l3out:
    description:
    - The L3 Out that contains the associated Route Profile.
    type: str
  host_based_routing:
    description:
    - Enables advertising host routes (/32 prefixes) out of the L3OUT(s) that are associated to this BD.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
    aliases: [ advertise_host_routes ]
  enable_rogue_except_mac:
    description:
    - Rogue exception MAC wildcard support for Bridge Domains.
    - Only available in APIC version 6.0 or later.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  allow_intersite_bum_traffic:
    description:
    - Control whether BUM traffic is allowed between sites.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
    aliases: [allow_bum_traffic]
  allow_intersite_l2_stretch:
    description:
    - Allow L2 Stretch between sites.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
    aliases: [allow_l2_stretch]
  allow_ipv6_multicast:
    description:
    - Flag to indicate if ipv6 multicast is enabled.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
    aliases: [ ipv6_multicast, ipv6_mcast, allow_ipv6_mcast]
  link_local_address:
    description:
    - The override of the system generated IPv6 link-local address.
    type: str
    aliases: [ ll_addr_ipv6, ll_addr, link_local]
  multicast_arp_drop:
    description:
    - Enable BD rogue multicast ARP packet drop.
    - Only available in APIC version 6.0 or later.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
    aliases: [ mcast_arp_drop ]
  vmac:
    description:
    - Virtual MAC address of the BD/SVI. This is used when the BD is extended to multiple sites using L2 Outside.
    type: str
  optimize_wan_bandwidth:
    description:
    - Optimize WAN Bandwidth improves the network application experience at the branch and makes better use of limited network resources.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
    aliases: [wan_optimization, opt_bandwidth]
  mld_snoop_policy:
    description:
    - The name of the Multicast Listener Discovery (MLD) Snooping Policy the Bridge Domain should use when overriding the default MLD Snooping Policy.
    - To delete this attribute, pass an empty string.
    type: str
    aliases: [mld_snoop, mld_policy]
  igmp_policy:
    description:
    - The name of the IGMP Interface Policy the Bridge Domain should use when overriding the default IGMP Interface Policy.
    - To delete this attribute, pass an empty string.
    type: str
    aliases: [igmp]
  vlan:
    description:
    - The selected VLAN for bridge domain access port encapsulation.
    - To delete this attribute, pass an empty string.
    type: str
    aliases: [encap]
  monitoring_policy:
    description:
    - The name of the Monitoring Policy to apply to the Bridge Domain.
    - To delete this attribute, pass an empty string.
    type: str
    aliases: [mon_pol, monitoring_pol]
  first_hop_security_policy:
    description:
    - The name of the First Hop Security Policy to apply to the Bridge Domain.
    - To delete this attribute, pass an empty string.
    type: str
    aliases: [fhsp, fhs_pol, fhsp_name]
  pim_source_filter:
    description:
    - The name of the PIM Source Filter to apply to the Bridge Domain.
    - To delete this attribute, pass an empty string.
    - Only available in APIC version 5.2 or later.
    type: str
    aliases: [pim_source]
  pim_destination_filter:
    description:
    - The name of the PIM Destination Filter to apply to the Bridge Domain.
    - To delete this attribute, pass an empty string.
    - Only available in APIC version 5.2 or later.
    type: str
    aliases: [pim_dest, pim_destination]

extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- The C(tenant) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:BD).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Add Bridge Domain
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
    tenant: prod
    bd: web_servers
    mac_address: 00:22:BD:F8:19:FE
    vrf: prod_vrf
    host_based_routing: true
    allow_intersite_bum_traffic: true
    allow_intersite_l2_stretch: true
    allow_ipv6_mcast: true
    ll_addr: "fe80::1322:33ff:fe44:5566"
    vmac: "00:AA:BB:CC:DD:03"
    optimize_wan_bandwidth: true
    vlan: vlan-101
    igmp_policy: web_servers_igmp_pol
    monitoring_policy: web_servers_monitoring_pol
    igmp_snoop_policy: web_servers_igmp_snoop
    mld_snoop_policy: web_servers_mld_snoop
    first_hop_security_policy: web_servers_fhs
    state: present
  delegate_to: localhost

- name: Add an FC Bridge Domain
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
    tenant: prod
    bd: storage
    bd_type: fc
    vrf: fc_vrf
    enable_routing: false
    state: present
  delegate_to: localhost

- name: Modify a Bridge Domain
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: true
    tenant: prod
    bd: web_servers
    arp_flooding: true
    l2_unknown_unicast: flood
    state: present
  delegate_to: localhost

- name: Modify a Bridge Domain to remove mld_snoop_policy and first_hop_security_policy
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: true
    tenant: prod
    bd: web_servers
    arp_flooding: true
    l2_unknown_unicast: flood
    mld_snoop_policy: ""
    first_hop_security_policy: ""
    state: present
  delegate_to: localhost

- name: Query All Bridge Domains
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: true
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a Bridge Domain
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: true
    tenant: prod
    bd: web_servers
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a Bridge Domain
  cisco.aci.aci_bd:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: true
    tenant: prod
    bd: web_servers
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
        arp_flooding=dict(type="bool"),
        bd=dict(type="str", aliases=["bd_name", "name"]),  # Not required for querying all objects
        bd_type=dict(type="str", choices=["ethernet", "fc"]),
        description=dict(type="str"),
        enable_multicast=dict(type="bool"),
        enable_routing=dict(type="bool"),
        endpoint_clear=dict(type="bool"),
        endpoint_move_detect=dict(type="str", choices=["default", "garp"]),
        endpoint_retention_action=dict(type="str", choices=["inherit", "resolve"]),
        endpoint_retention_policy=dict(type="str"),
        igmp_snoop_policy=dict(type="str"),
        ip_learning=dict(type="bool"),
        ipv6_nd_policy=dict(type="str"),
        l2_unknown_unicast=dict(type="str", choices=["proxy", "flood"]),
        l3_unknown_multicast=dict(type="str", choices=["flood", "opt-flood"]),
        ipv6_l3_unknown_multicast=dict(type="str", choices=["flood", "opt-flood"]),
        limit_ip_learn=dict(type="bool"),
        mac_address=dict(type="str", aliases=["mac"]),
        multi_dest=dict(type="str", choices=["bd-flood", "drop", "encap-flood"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        vrf=dict(type="str", aliases=["vrf_name"]),
        route_profile=dict(type="str"),
        route_profile_l3out=dict(type="str"),
        name_alias=dict(type="str"),
        host_based_routing=dict(type="bool", aliases=["advertise_host_routes"]),
        enable_rogue_except_mac=dict(type="bool"),
        allow_intersite_bum_traffic=dict(type="bool", aliases=["allow_bum_traffic"]),
        allow_intersite_l2_stretch=dict(type="bool", aliases=["allow_l2_stretch"]),
        allow_ipv6_multicast=dict(type="bool", aliases=["ipv6_multicast", "ipv6_mcast", "allow_ipv6_mcast"]),
        link_local_address=dict(type="str", aliases=["ll_addr_ipv6", "ll_addr", "link_local"]),
        multicast_arp_drop=dict(type="bool", aliases=["mcast_arp_drop"]),
        vmac=dict(type="str"),
        optimize_wan_bandwidth=dict(type="bool", aliases=["wan_optimization", "opt_bandwidth"]),
        mld_snoop_policy=dict(type="str", aliases=["mld_snoop", "mld_policy"]),
        igmp_policy=dict(type="str", aliases=["igmp"]),
        vlan=dict(type="str", aliases=["encap"]),
        monitoring_policy=dict(type="str", aliases=["mon_pol", "monitoring_pol"]),
        first_hop_security_policy=dict(type="str", aliases=["fhsp", "fhs_pol", "fhsp_name"]),
        pim_source_filter=dict(type="str", aliases=["pim_source"]),
        pim_destination_filter=dict(type="str", aliases=["pim_dest", "pim_destination"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["bd", "tenant"]],
            ["state", "present", ["bd", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    arp_flooding = aci.boolean(module.params.get("arp_flooding"))
    bd = module.params.get("bd")
    bd_type = module.params.get("bd_type")
    if bd_type == "ethernet":
        # ethernet type is represented as regular, but that is not clear to the users
        bd_type = "regular"
    description = module.params.get("description")
    enable_multicast = aci.boolean(module.params.get("enable_multicast"))
    enable_routing = aci.boolean(module.params.get("enable_routing"))
    endpoint_clear = aci.boolean(module.params.get("endpoint_clear"))
    endpoint_move_detect = module.params.get("endpoint_move_detect")
    if endpoint_move_detect == "default":
        # the ACI default setting is an empty string, but that is not a good input value
        endpoint_move_detect = ""
    endpoint_retention_action = module.params.get("endpoint_retention_action")
    endpoint_retention_policy = module.params.get("endpoint_retention_policy")
    igmp_snoop_policy = module.params.get("igmp_snoop_policy")
    ip_learning = aci.boolean(module.params.get("ip_learning"))
    ipv6_nd_policy = module.params.get("ipv6_nd_policy")
    l2_unknown_unicast = module.params.get("l2_unknown_unicast")
    l3_unknown_multicast = module.params.get("l3_unknown_multicast")
    ipv6_l3_unknown_multicast = module.params.get("ipv6_l3_unknown_multicast")
    limit_ip_learn = aci.boolean(module.params.get("limit_ip_learn"))
    mac_address = module.params.get("mac_address")
    multi_dest = module.params.get("multi_dest")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    vrf = module.params.get("vrf")
    route_profile = module.params.get("route_profile")
    route_profile_l3out = module.params.get("route_profile_l3out")
    name_alias = module.params.get("name_alias")
    host_based_routing = aci.boolean(module.params.get("host_based_routing"))
    enable_rogue_except_mac = aci.boolean(module.params.get("enable_rogue_except_mac"))
    allow_intersite_bum_traffic = aci.boolean(module.params.get("allow_intersite_bum_traffic"))
    allow_intersite_l2_stretch = aci.boolean(module.params.get("allow_intersite_l2_stretch"))
    allow_ipv6_multicast = aci.boolean(module.params.get("allow_ipv6_multicast"))
    link_local_address = module.params.get("link_local_address")
    multicast_arp_drop = aci.boolean(module.params.get("multicast_arp_drop"))
    vmac = module.params.get("vmac")
    optimize_wan_bandwidth = aci.boolean(module.params.get("optimize_wan_bandwidth"))
    mld_snoop_policy = module.params.get("mld_snoop_policy")
    igmp_policy = module.params.get("igmp_policy")
    vlan = module.params.get("vlan")
    monitoring_policy = module.params.get("monitoring_policy")
    first_hop_security_policy = module.params.get("first_hop_security_policy")
    pim_source_filter = module.params.get("pim_source_filter")
    pim_destination_filter = module.params.get("pim_destination_filter")

    child_classes = [
        "fvRsCtx",
        "fvRsIgmpsn",
        "fvRsBDToNdP",
        "fvRsBdToEpRet",
        "fvRsBDToProfile",
        "fvRsMldsn",
        "igmpIfP",
        "igmpRsIfPol",
        "fvAccP",
        "fvRsABDPolMonPol",
        "fvRsBDToFhs",
    ]
    if pim_source_filter is not None or pim_destination_filter is not None:
        # Only valid for APIC verion 5.2+
        child_classes.extend(
            [
                "pimBDP",
                "pimBDFilterPol",
                "pimBDSrcFilterPol",
                "pimBDDestFilterPol",
                "rtdmcRsFilterToRtMapPol",
            ]
        )
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvBD",
            aci_rn="BD-{0}".format(bd),
            module_object=bd,
            target_filter={"name": bd},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        class_config = dict(
            arpFlood=arp_flooding,
            descr=description,
            epClear=endpoint_clear,
            epMoveDetectMode=endpoint_move_detect,
            ipLearning=ip_learning,
            limitIpLearnToSubnets=limit_ip_learn,
            mac=mac_address,
            mcastAllow=enable_multicast,
            multiDstPktAct=multi_dest,
            name=bd,
            type=bd_type,
            unicastRoute=enable_routing,
            unkMacUcastAct=l2_unknown_unicast,
            unkMcastAct=l3_unknown_multicast,
            nameAlias=name_alias,
            enableRogueExceptMac=enable_rogue_except_mac,
            hostBasedRouting=host_based_routing,
            intersiteBumTrafficAllow=allow_intersite_bum_traffic,
            intersiteL2Stretch=allow_intersite_l2_stretch,
            ipv6McastAllow=allow_ipv6_multicast,
            llAddr=link_local_address,
            mcastARPDrop=multicast_arp_drop,
            vmac=vmac,
            OptimizeWanBandwidth=optimize_wan_bandwidth,
        )

        if ipv6_l3_unknown_multicast is not None:
            class_config["v6unkMcastAct"] = ipv6_l3_unknown_multicast

        child_configs = [
            {"fvRsCtx": {"attributes": {"tnFvCtxName": vrf}}},
            {"fvRsIgmpsn": {"attributes": {"tnIgmpSnoopPolName": igmp_snoop_policy}}},
            {"fvRsMldsn": {"attributes": {"tnMldSnoopPolName": mld_snoop_policy}}},
            {"fvRsBDToNdP": {"attributes": {"tnNdIfPolName": ipv6_nd_policy}}},
            {"fvRsBdToEpRet": {"attributes": {"resolveAct": endpoint_retention_action, "tnFvEpRetPolName": endpoint_retention_policy}}},
            {"fvRsBDToProfile": {"attributes": {"tnL3extOutName": route_profile_l3out, "tnRtctrlProfileName": route_profile}}},
            {"fvRsBDToFhs": {"attributes": {"tnFhsBDPolName": first_hop_security_policy}}},
            {"fvAccP": {"attributes": {"encap": vlan}}},
            {"fvRsABDPolMonPol": {"attributes": {"tnMonEPGPolName": monitoring_policy}}},
        ]

        if igmp_policy is not None:
            igmp_policy_tdn = "" if igmp_policy == "" else "uni/tn-{0}/igmpIfPol-{1}".format(tenant, igmp_policy)
            child_configs.append({"igmpIfP": {"attributes": {}, "children": [{"igmpRsIfPol": {"attributes": {"tDn": igmp_policy_tdn}}}]}})
        if pim_source_filter is not None or pim_destination_filter is not None:
            pim_bd = {"pimBDP": {"attributes": {}, "children": []}}
            pim_filter_pol = {"pimBDFilterPol": {"attributes": {}, "children": []}}
            if pim_source_filter is not None:
                pim_source_filter_tdn = "" if pim_source_filter == "" else "uni/tn-{0}/rtmap-{1}".format(tenant, pim_source_filter)
                pim_filter_pol["pimBDFilterPol"]["children"].append(
                    {"pimBDSrcFilterPol": {"attributes": {}, "children": [{"rtdmcRsFilterToRtMapPol": {"attributes": {"tDn": pim_source_filter_tdn}}}]}}
                )
            if pim_destination_filter is not None:
                pim_destination_filter_tdn = "" if pim_destination_filter == "" else "uni/tn-{0}/rtmap-{1}".format(tenant, pim_destination_filter)
                pim_filter_pol["pimBDFilterPol"]["children"].append(
                    {"pimBDDestFilterPol": {"attributes": {}, "children": [{"rtdmcRsFilterToRtMapPol": {"attributes": {"tDn": pim_destination_filter_tdn}}}]}}
                )
            pim_bd["pimBDP"]["children"].append(pim_filter_pol)
            child_configs.append(pim_bd)

        aci.payload(aci_class="fvBD", class_config=class_config, child_configs=child_configs)

        aci.get_diff(aci_class="fvBD")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
