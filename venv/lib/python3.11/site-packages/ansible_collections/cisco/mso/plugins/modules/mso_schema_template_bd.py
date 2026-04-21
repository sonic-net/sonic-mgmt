#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2021, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_bd
short_description: Manage Bridge Domains (BDs) in schema templates
description:
- Manage BDs in schema templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
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
    - Display Name of template for operations can only be used in some versions of mso.
    - Use the name of template instead of Display Name to avoid discrepency.
    type: str
    required: true
  bd:
    description:
    - The name of the BD to manage.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  description:
    description:
    - The description of BD is supported on versions of MSO that are 3.3 or greater.
    type: str
  vrf:
    description:
    - The VRF associated to this BD. This is required only when creating a new BD.
    type: dict
    suboptions:
      name:
        description:
        - The name of the VRF to associate with.
        required: true
        type: str
      schema:
        description:
        - The schema that defines the referenced VRF.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      template:
        description:
        - The template that defines the referenced VRF.
        - If this parameter is unspecified, it defaults to the current template.
        type: str
  dhcp_policy:
    description:
      - The DHCP Policy
    type: dict
    suboptions:
      name:
        description:
        - The name of the DHCP Relay Policy
        type: str
        required: true
      version:
        description:
        - The version of DHCP Relay Policy
        type: int
        required: true
      dhcp_option_policy:
        description:
        - The DHCP Option Policy
        type: dict
        suboptions:
          name:
            description:
            - The name of the DHCP Option Policy
            type: str
            required: true
          version:
            description:
            - The version of the DHCP Option Policy
            type: int
            required: true
  dhcp_policies:
    description:
    - A list DHCP Policies to be assciated with the BD
    - This option can only be used on versions of MSO that are 3.1.1h or greater.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the DHCP Relay Policy
        type: str
        required: true
      version:
        description:
        - The version of DHCP Relay Policy
        type: int
        required: true
      dhcp_option_policy:
        description:
        - The DHCP Option Policy
        type: dict
        suboptions:
          name:
            description:
            - The name of the DHCP Option Policy
            type: str
            required: true
          version:
            description:
            - The version of the DHCP Option Policy
            type: int
            required: true
  subnets:
    description:
    - The subnets associated to this BD.
    type: list
    elements: dict
    suboptions:
      subnet:
        description:
        - The IP range in CIDR notation.
        type: str
        required: true
        aliases: [ ip ]
      description:
        description:
        - The description of this subnet.
        type: str
      scope:
        description:
        - The scope of the subnet.
        type: str
        default: private
        choices: [ private, public ]
      shared:
        description:
        - Whether this subnet is shared between VRFs.
        type: bool
        default: false
      no_default_gateway:
        description:
        - Whether this subnet has a default gateway.
        type: bool
        default: false
      querier:
        description:
        - Whether this subnet is an IGMP querier.
        type: bool
        default: false
      virtual:
        description:
        - Treat as Virtual IP Address.
        type: bool
        default: false
      primary:
        description:
        - Treat as Primary Subnet.
        - There can be only one primary subnet per address family under a BD.
        - This option can only be used on versions of MSO that are 3.1.1h or greater.
        type: bool
        default: false
  intersite_bum_traffic:
    description:
    - Whether to allow intersite BUM traffic.
    type: bool
  optimize_wan_bandwidth:
    description:
    - Whether to optimize WAN bandwidth.
    type: bool
  layer2_stretch:
    description:
    - Whether to enable L2 stretch.
    type: bool
    default: true
  layer2_unknown_unicast:
    description:
    - Layer2 unknown unicast.
    type: str
    choices: [ flood, proxy ]
  layer3_multicast:
    description:
    - Whether to enable L3 multicast.
    type: bool
  unknown_multicast_flooding:
    description:
    - Unknown Multicast Flooding can either be Flood or Optimized Flooding.
    type: str
    choices: [ flood, optimized_flooding ]
  multi_destination_flooding:
    description:
    - Multi-Destination Flooding can either be Flood in BD, Drop or Flood in Encapsulation.
    - Flood in Encapsulation is only supported on versions of MSO that are 3.3 or greater.
    type: str
    choices: [ flood_in_bd, drop, encap-flood ]
  ipv6_unknown_multicast_flooding:
    description:
    - IPv6 Unknown Multicast Flooding can either be Flood or Optimized Flooding
    type: str
    choices: [ flood, optimized_flooding ]
  arp_flooding:
    description:
    - ARP Flooding
    type: bool
  virtual_mac_address:
    description:
    - Virtual MAC Address
    type: str
  unicast_routing:
    description:
    - Unicast Routing
    - This option can only be used on versions of MSO that are 3.1.1h or greater.
    type: bool
  multicast_route_map_source_filter:
    description:
    - The name of the Route Map Source Filter.
    - The Route Map Source Filter must reside in the same tenant as the tenant associated to the schema.
    - This option can only be used when the BD has Layer 3 Multicast enabled.
    - Providing an empty string O(multicast_route_map_source_filter="") will remove the Route Map Source Filter from the BD.
    type: str
  multicast_route_map_destination_filter:
    description:
    - The name of the Route Map Destination Filter.
    - The Route Map Destination Filter must reside in the same tenant as the tenant associated to the schema.
    - This option can only be used when the BD has Layer 3 Multicast enabled.
    - Providing an empty string O(multicast_route_map_destination_filter="") will remove the Route Map Destination Filter from the BD.
    type: str
  ep_move_detection_mode:
    description:
    - Enables detection of endpoint moves using Gratuitous ARP (GARP) packets.
    type: bool
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
- name: Add a new BD
  cisco.mso.mso_schema_template_bd:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD 1
    vrf:
      name: VRF1
    state: present

- name: Add a new BD from another Schema
  mso_schema_template_bd:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD 1
    vrf:
      name: VRF1
      schema: Schema Origin
      template: Template Origin
    state: present

- name: Add bd with options available on version 3.1
  mso_schema_template_bd:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD 1
    intersite_bum_traffic: true
    optimize_wan_bandwidth: false
    layer2_stretch: true
    layer2_unknown_unicast: flood
    layer3_multicast: false
    unknown_multicast_flooding: flood
    multi_destination_flooding: drop
    ipv6_unknown_multicast_flooding: flood
    arp_flooding: false
    virtual_mac_address: 00:00:5E:00:01:3C
    subnets:
      - subnet: 10.0.0.128/24
      - subnet: 10.0.1.254/24
        description: 1234567890
      - ip: 192.168.0.254/24
        description: "My description for a subnet"
        scope: private
        shared: false
        no_default_gateway: true
    vrf:
      name: vrf1
      schema: Test
      template: Template1
    dhcp_policy:
      name: ansible_test
      version: 1
      dhcp_option_policy:
        name: ansible_test_option
        version: 1
    state: present

- name: Add bd with options available on version 3.1.1h or greater
  mso_schema_template_bd:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD 1
    intersite_bum_traffic: true
    optimize_wan_bandwidth: false
    layer2_stretch: true
    layer2_unknown_unicast: flood
    layer3_multicast: false
    unknown_multicast_flooding: flood
    multi_destination_flooding: drop
    ipv6_unknown_multicast_flooding: flood
    arp_flooding: false
    virtual_mac_address: 00:00:5E:00:01:3C
    unicast_routing: true
    subnets:
      - subnet: 10.0.0.128/24
        primary: true
      - subnet: 10.0.1.254/24
        description: 1234567890
        virtual: true
      - ip: 192.168.0.254/24
        description: "My description for a subnet"
        scope: private
        shared: false
        no_default_gateway: true
    vrf:
      name: vrf1
      schema: Schema1
      template: Template1
    dhcp_policies:
      - name: ansible_test
        version: 1
        dhcp_option_policy:
          name: ansible_test_option
          version: 1
      - name: ansible_test2
        version: 1
        dhcp_option_policy:
          name: ansible_test_option2
          version: 1
      - name: ansible_test3
        version: 1
        dhcp_option_policy:
          name: ansible_test_option
          version: 1
    state: present

- name: Remove a BD
  cisco.mso.mso_schema_template_bd:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD1
    state: absent

- name: Query a specific BD
  cisco.mso.mso_schema_template_bd:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    bd: BD1
    state: query
  register: query_result

- name: Query all BDs
  cisco.mso.mso_schema_template_bd:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: query
  register: query_result
"""

RETURN = r"""
"""


import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_reference_spec, mso_bd_subnet_spec, mso_dhcp_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        bd=dict(type="str", aliases=["name"]),  # This parameter is not required for querying all objects
        display_name=dict(type="str"),
        description=dict(type="str"),
        intersite_bum_traffic=dict(type="bool"),
        optimize_wan_bandwidth=dict(type="bool"),
        layer2_stretch=dict(type="bool", default="true"),
        layer2_unknown_unicast=dict(type="str", choices=["flood", "proxy"]),
        layer3_multicast=dict(type="bool"),
        vrf=dict(type="dict", options=mso_reference_spec()),
        dhcp_policy=dict(type="dict", options=mso_dhcp_spec()),
        dhcp_policies=dict(type="list", elements="dict", options=mso_dhcp_spec()),
        subnets=dict(type="list", elements="dict", options=mso_bd_subnet_spec()),
        unknown_multicast_flooding=dict(type="str", choices=["optimized_flooding", "flood"]),
        multi_destination_flooding=dict(type="str", choices=["flood_in_bd", "drop", "encap-flood"]),
        ipv6_unknown_multicast_flooding=dict(type="str", choices=["optimized_flooding", "flood"]),
        arp_flooding=dict(type="bool"),
        virtual_mac_address=dict(type="str"),
        unicast_routing=dict(type="bool"),
        multicast_route_map_source_filter=dict(type="str"),
        multicast_route_map_destination_filter=dict(type="str"),
        ep_move_detection_mode=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["bd"]],
            ["state", "present", ["bd", "vrf"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    bd = module.params.get("bd")
    display_name = module.params.get("display_name")
    description = module.params.get("description")
    intersite_bum_traffic = module.params.get("intersite_bum_traffic")
    optimize_wan_bandwidth = module.params.get("optimize_wan_bandwidth")
    layer2_stretch = module.params.get("layer2_stretch")
    layer2_unknown_unicast = module.params.get("layer2_unknown_unicast")
    layer3_multicast = module.params.get("layer3_multicast")
    vrf = module.params.get("vrf")
    if vrf is not None and vrf.get("template") is not None:
        vrf["template"] = vrf.get("template").replace(" ", "")
    dhcp_policy = module.params.get("dhcp_policy")
    dhcp_policies = module.params.get("dhcp_policies")
    subnets = module.params.get("subnets")
    unknown_multicast_flooding = module.params.get("unknown_multicast_flooding")
    multi_destination_flooding = module.params.get("multi_destination_flooding")
    ipv6_unknown_multicast_flooding = module.params.get("ipv6_unknown_multicast_flooding")
    arp_flooding = module.params.get("arp_flooding")
    virtual_mac_address = module.params.get("virtual_mac_address")
    unicast_routing = module.params.get("unicast_routing")
    multicast_route_map_source_filter = module.params.get("multicast_route_map_source_filter")
    multicast_route_map_destination_filter = module.params.get("multicast_route_map_destination_filter")
    ep_move_detection_mode = module.params.get("ep_move_detection_mode")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Map choices
    if unknown_multicast_flooding == "optimized_flooding":
        unknown_multicast_flooding = "opt-flood"
    if ipv6_unknown_multicast_flooding == "optimized_flooding":
        ipv6_unknown_multicast_flooding = "opt-flood"
    if multi_destination_flooding == "flood_in_bd":
        multi_destination_flooding = "bd-flood"

    if layer2_unknown_unicast == "flood":
        arp_flooding = True

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))
    template_idx = templates.index(template)

    # Get BDs
    bds = [b.get("name") for b in schema_obj.get("templates")[template_idx]["bds"]]

    if bd is not None and bd in bds:
        bd_idx = bds.index(bd)
        mso.existing = schema_obj.get("templates")[template_idx]["bds"][bd_idx]

    if state == "query":
        if bd is None:
            mso.existing = schema_obj.get("templates")[template_idx]["bds"]
        elif not mso.existing:
            mso.fail_json(msg="BD '{bd}' not found".format(bd=bd))
        mso.exit_json()

    if multicast_route_map_source_filter or multicast_route_map_destination_filter:
        if not layer3_multicast:
            mso.fail_json(msg="Layer 3 Multicast must be enabled to use Multicast Route Map Filters.")
        source_id, destination_id = get_route_map_filter_uuids(
            mso, schema_obj.get("templates")[template_idx].get("tenantId"), multicast_route_map_source_filter, multicast_route_map_destination_filter
        )

    bds_path = "/templates/{0}/bds".format(template)
    bd_path = "/templates/{0}/bds/{1}".format(template, bd)
    ops = []

    mso.previous = copy.deepcopy(mso.existing)
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=bd_path))

    elif state == "present":
        vrf_ref = mso.make_reference(vrf, "vrf", schema_id, template)
        subnets = mso.make_subnets(subnets)
        dhcp_label = mso.make_dhcp_label(dhcp_policy)
        dhcp_labels = mso.make_dhcp_label(dhcp_policies)

        if display_name is None and not mso.existing:
            display_name = bd
        if subnets is None and not mso.existing:
            subnets = []
        mso_remove_values = []
        payload = dict(
            name=bd,
            displayName=display_name,
            intersiteBumTrafficAllow=intersite_bum_traffic,
            optimizeWanBandwidth=optimize_wan_bandwidth,
            l2UnknownUnicast=layer2_unknown_unicast,
            l2Stretch=layer2_stretch,
            l3MCast=layer3_multicast,
            subnets=subnets,
            vrfRef=vrf_ref,
            dhcpLabel=dhcp_label,
            unkMcastAct=unknown_multicast_flooding,
            multiDstPktAct=multi_destination_flooding,
            v6unkMcastAct=ipv6_unknown_multicast_flooding,
            vmac=virtual_mac_address,
            arpFlood=arp_flooding,
        )

        if dhcp_labels:
            payload.update(dhcpLabels=dhcp_labels)

        if unicast_routing is not None:
            payload.update(unicastRouting=unicast_routing)

        if description:
            payload.update(description=description)

        if multicast_route_map_source_filter or multicast_route_map_destination_filter:
            route_map_filter = {}

            # Static setting defined version and mcastRtMapDestVersion to 0 are set in UI but seem not required so excluding them
            # If in future this is required then uncomment the below line
            # route_map_filter = {"version": 0, "mcastRtMapDestVersion": 0}

            if source_id:
                route_map_filter["mcastRtMapSourceRef"] = source_id
            if destination_id:
                route_map_filter["mcastRtMapDestRef"] = destination_id
            payload.update(mcastRtMapFilter=route_map_filter)
        elif multicast_route_map_source_filter == "" and multicast_route_map_destination_filter == "" and mso.existing.get("mcastRtMapFilter"):
            mso_remove_values.append("mcastRtMapFilter")
            mso.existing.pop("mcastRtMapFilter")

        if ep_move_detection_mode:
            payload.update(epMoveDetectMode="garp")
        elif ep_move_detection_mode is False:
            payload.update(epMoveDetectMode="none")

        mso.sanitize(payload, collate=True, required=["dhcpLabel", "dhcpLabels"])

        if mso.existing:
            # When updating an existing BD, replace operation for each attribute to avoid existing configuration being replaced
            # This case is specifically important for subnet and dhcp policy which can be configured as a child module
            append_update_ops_data(ops, copy.deepcopy(mso.existing), bd_path, payload, mso_remove_values)
        else:
            ops.append(dict(op="add", path=bds_path + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if "bdRef" in mso.previous:
        del mso.previous["bdRef"]
    if "vrfRef" in mso.previous:
        if isinstance(mso.previous.get("vrfRef"), dict):
            mso.previous["vrfRef"] = mso.previous.get("vrfRef")
        else:
            mso.previous["vrfRef"] = mso.vrf_dict_from_ref(mso.previous.get("vrfRef"))

    if not module.check_mode and mso.proposed != mso.previous:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


def get_route_map_filter_uuids(mso, tenant_id, multicast_route_map_source_filter, multicast_route_map_destination_filter):
    source_id, destination_id = None, None

    # Only tenant type templates contain the correct route map policies
    # Retrieves the list templates that contain the same tenant because only route map policies for the tenant assigned to the schema are options to be chosen
    templates = [
        MSOTemplate(mso, template_id=template.get("templateId")) for template in MSOTemplate(mso, "tenant").template if template.get("tenantId") == tenant_id
    ]

    # NDO restricts route map policies in the same tenant to have the same name thus we can loop through the route map policies to find the correct uuid
    for template in templates:
        for route_map_policy in template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("mcastRouteMapPolicies", []):
            if multicast_route_map_source_filter and route_map_policy.get("name") == multicast_route_map_source_filter:
                source_id = route_map_policy.get("uuid")
            if multicast_route_map_destination_filter and route_map_policy.get("name") == multicast_route_map_destination_filter:
                destination_id = route_map_policy.get("uuid")
            if (multicast_route_map_source_filter is None or source_id) and (multicast_route_map_destination_filter is None or destination_id):
                break
        if (multicast_route_map_source_filter is None or source_id) and (multicast_route_map_destination_filter is None or destination_id):
            break

    # Error handling for when N amount of route map policies are not found
    error_message = ""
    if multicast_route_map_source_filter and not source_id:
        error_message = "Route Map Source Filter '{0}' not found.".format(multicast_route_map_source_filter)
    if multicast_route_map_destination_filter and not destination_id:
        if error_message == "":
            error_message = "Route Map Destination Filter '{0}' not found.".format(multicast_route_map_destination_filter)
        else:
            error_message += "\nRoute Map Destination Filter '{0}' not found.".format(multicast_route_map_destination_filter)
    if error_message:
        mso.fail_json(msg=error_message)

    return source_id, destination_id


if __name__ == "__main__":
    main()
