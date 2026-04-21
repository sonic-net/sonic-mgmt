#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: aci_l3out_bgp_peer
short_description: Manage Layer 3 Outside (L3Out) BGP Peers (bgp:PeerP and bgp:InfraPeerP)
description:
- Manage L3Out BGP Peers on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - Name of an existing L3Out.
    type: str
    aliases: [ l3out_name ]
  node_profile:
    description:
    - Name of the node profile.
    type: str
    aliases: [ node_profile_name, logical_node ]
  interface_profile:
    description:
    - Name of the interface profile.
    type: str
    aliases: [ interface_profile_name, logical_interface ]
  pod_id:
    description:
    - Pod to build the interface on.
    type: str
  node_id:
    description:
    - Node to build the interface on for Port-channels and single ports.
    - Hyphen separated pair of nodes (e.g. "201-202") for vPCs.
    type: str
  path_ep:
    description:
    - Path to interface
    - Interface Port Group name for Port-channels and vPCs
    - Port number for single ports (e.g. "eth1/12")
    type: str
  peer_ip:
    description:
    - IP address of the BGP peer.
    type: str
  remote_asn:
    description:
    - Autonomous System Number of the BGP peer.
    type: int
  bgp_controls:
    description:
    - BGP Controls
    type: list
    elements: str
    choices: [ send-com, send-ext-com, allow-self-as, as-override, dis-peer-as-check, nh-self, send-domain-path ]
  peer_controls:
    description:
    - Peer Controls
    type: list
    elements: str
    choices: [ bfd, dis-conn-check ]
  address_type_controls:
    description:
    - Address Type Controls
    type: list
    elements: str
    choices: [ af-ucast, af-mcast ]
  private_asn_controls:
    description:
    - Private AS Controls
    type: list
    elements: str
    choices: [ remove-exclusive, remove-all, replace-as ]
  ttl:
    description:
    - eBGP Multihop Time To Live
    type: int
  weight:
    description:
    - Weight for BGP routes from this neighbor
    type: int
  admin_state:
    description:
    - Admin state for the BGP session
    type: str
    choices: [ enabled, disabled ]
  allow_self_as_count:
    description:
    - Number of allowed self AS.
    - Only used if C(allow-self-as) is enabled under C(bgp_controls).
    type: int
  route_control_profiles:
    description:
    - List of dictionaries objects, which is used to bind the BGP Peer Connectivity Profile to Route Control Profile.
    type: list
    elements: dict
    suboptions:
      tenant:
        description:
        - Name of the tenant.
        type: str
        required: true
      profile:
        description:
        - Name of the Route Control Profile.
        type: str
        required: true
      l3out:
        description:
        - Name of the L3 Out.
        type: str
      direction:
        description:
        - Name of the Route Control Profile direction.
        type: str
        required: true
  local_as_number_config:
    description:
    - The local Autonomous System Number (ASN) configuration of the L3Out BGP Peer.
    - The APIC defaults to C(none) when unset during creation.
    type: str
    choices: [ dual-as, no-prepend, none, replace-as ]
    aliases: [ local_as_num_config ]
  local_as_number:
    description:
    - The local Autonomous System Number (ASN) of the L3Out BGP Peer.
    - The APIC defaults to 0 when unset during creation.
    type: int
    aliases: [ local_as_num ]
  bgp_password:
    description:
    - Password for the BGP Peer.
    - Providing the password will always result in a change because the set password cannot be retrieved from APIC.
    type: str
  description:
    description:
    - Description for the BGP Peer.
    type: str
    aliases: [ descr ]
  transport_data_plane:
    description:
    - Transport Data Plane type.
    type: str
    choices: [ mpls, sr_mpls ]
  bgp_peer_prefix_policy:
    description:
    - BGP Peer Prefix Policy.
    - BGP Peer Prefix Policy is only allowed to be configured when I(bgp_infra_peer=true).
    type: str
    aliases: [ bgp_peer_prefix_policy_name ]
  peer_type:
    description:
    - BGP Peer type.
    type: str
    choices: [ sr_mpls ]
  bgp_infra_peer:
    description:
    - BGP Infra peer (bgp:InfraPeerP).
    type: bool
    aliases: [ infra ]
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

seealso:
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_l3out_logical_node_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(bgp:peerP) and B(bgp:InfraPeerP)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new BGP peer on a physical interface
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    path_ep: eth1/12
    peer_ip: 192.168.10.2
    remote_asn: 65456
    bgp_controls:
      - nh-self
      - send-com
      - send-ext-com
    peer_controls:
      - bfd
    route_control_profiles:
      - tenant: "ansible_tenant"
        profile: "anstest_import"
        direction: "import"
      - tenant: "ansible_tenant"
        profile: "anstest_export"
        direction: "export"
        l3out: "anstest_l3out"
        state: present
  delegate_to: localhost

- name: Add a new BGP peer on a vPC
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201-202
    path_ep: my_vpc_ipg
    peer_ip: 192.168.20.2
    remote_asn: 65457
    ttl: 4
    weight: 50
    state: present
  delegate_to: localhost

- name: Create Infra BGP Peer with password
  aci_l3out_bgp_peer: &infra_bgp_peer
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: infra
    l3out: ansible_infra_l3out
    node_profile: ansible_infra_l3out_node_profile
    ttl: 2
    bgp_infra_peer: true
    bgp_password: ansible_test_password
    peer_ip: 192.168.50.2
    remote_asn: 65450
    local_as_number: 65460
    peer_type: sr_mpls
    bgp_controls:
      - send-domain-path
    transport_data_plane: sr_mpls
    bgp_peer_prefix_policy: ansible_peer_prefix_profile
    state: present
  delegate_to: localhost

- name: Shutdown a BGP peer
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    path_ep: eth1/12
    peer_ip: 192.168.10.2
    admin_state: disabled
    state: present
  delegate_to: localhost

- name: Delete a BGP peer
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    path_ep: eth1/12
    peer_ip: 192.168.10.2
    state: absent
  delegate_to: localhost

- name: Add BGP Peer to the Node Profile level
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: ansible_tenant
    l3out: ansible_l3out
    node_profile: ansible_node_profile
    peer_ip: 192.168.50.3
    route_control_profiles:
      - tenant: "ansible_tenant"
        profile: "anstest_import"
        direction: "import"
      - tenant: "ansible_tenant"
        profile: "anstest_export"
        direction: "export"
        l3out: "anstest_l3out"
    state: present
  delegate_to: localhost

- name: Query a BGP peer
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    path_ep: eth1/12
    peer_ip: 192.168.10.2
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all BGP peer
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_all

- name: Query all BGP infra peer
  cisco.aci.aci_l3out_bgp_peer:
    host: apic
    username: admin
    password: SomeSecretPassword
    bgp_infra_peer: true
    state: query
  delegate_to: localhost
  register: query_all
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
    route_control_profile_spec,
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        description=dict(type="str", aliases=["descr"]),
        node_profile=dict(type="str", aliases=["node_profile_name", "logical_node"]),
        interface_profile=dict(type="str", aliases=["interface_profile_name", "logical_interface"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        pod_id=dict(type="str"),
        node_id=dict(type="str"),
        path_ep=dict(type="str"),
        peer_ip=dict(type="str"),
        remote_asn=dict(type="int"),
        bgp_controls=dict(
            type="list",
            elements="str",
            choices=[
                "send-com",
                "send-ext-com",
                "allow-self-as",
                "as-override",
                "dis-peer-as-check",
                "nh-self",
                "send-domain-path",
            ],
        ),
        peer_controls=dict(type="list", elements="str", choices=["bfd", "dis-conn-check"]),
        address_type_controls=dict(type="list", elements="str", choices=["af-ucast", "af-mcast"]),
        private_asn_controls=dict(
            type="list",
            elements="str",
            choices=["remove-exclusive", "remove-all", "replace-as"],
        ),
        ttl=dict(type="int"),
        weight=dict(type="int"),
        admin_state=dict(type="str", choices=["enabled", "disabled"]),
        allow_self_as_count=dict(type="int"),
        route_control_profiles=dict(
            type="list",
            elements="dict",
            options=route_control_profile_spec(),
        ),
        local_as_number_config=dict(type="str", choices=["dual-as", "no-prepend", "none", "replace-as"], aliases=["local_as_num_config"]),
        local_as_number=dict(type="int", aliases=["local_as_num"]),
        bgp_password=dict(type="str", no_log=True),
        transport_data_plane=dict(type="str", choices=["mpls", "sr_mpls"]),
        bgp_peer_prefix_policy=dict(type="str", aliases=["bgp_peer_prefix_policy_name"]),
        peer_type=dict(type="str", choices=["sr_mpls"]),
        bgp_infra_peer=dict(type="bool", aliases=["infra"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "l3out", "node_profile", "peer_ip"]],
            ["state", "present", ["tenant", "l3out", "node_profile", "peer_ip"]],
        ],
        required_together=[["interface_profile", "pod_id", "node_id", "path_ep"]],
    )

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    description = module.params.get("description")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
    state = module.params.get("state")
    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    path_ep = module.params.get("path_ep")
    peer_ip = module.params.get("peer_ip")
    remote_asn = module.params.get("remote_asn")
    bgp_controls = module.params.get("bgp_controls")
    peer_controls = module.params.get("peer_controls")
    address_type_controls = sorted(module.params.get("address_type_controls") or [])
    private_asn_controls = module.params.get("private_asn_controls")
    ttl = module.params.get("ttl")
    weight = module.params.get("weight")
    admin_state = module.params.get("admin_state")
    allow_self_as_count = module.params.get("allow_self_as_count")
    route_control_profiles = module.params.get("route_control_profiles")
    local_as_number_config = module.params.get("local_as_number_config")
    local_as_number = module.params.get("local_as_number")
    bgp_password = module.params.get("bgp_password")
    transport_data_plane = module.params.get("transport_data_plane")
    peer_type = module.params.get("peer_type")
    bgp_infra_peer = module.params.get("bgp_infra_peer")
    bgp_peer_prefix_policy = module.params.get("bgp_peer_prefix_policy")

    aci = ACIModule(module)
    if node_id:
        if "-" in node_id:
            path_type = "protpaths"
        else:
            path_type = "paths"

        path_dn = "topology/pod-{0}/{1}-{2}/pathep-[{3}]".format(pod_id, path_type, node_id, path_ep)

    child_configs = []
    child_classes = ["bgpRsPeerPfxPol", "bgpAsP", "bgpLocalAsnP"]
    aci_class = "bgpInfraPeerP" if bgp_infra_peer else "bgpPeerP"

    if remote_asn is not None:
        bgp_as_p = dict(bgpAsP=dict(attributes=dict(asn=remote_asn)))
        if remote_asn == 0:
            bgp_as_p["bgpAsP"]["attributes"]["status"] = "deleted"
        child_configs.append(bgp_as_p)

    if local_as_number_config is not None or local_as_number is not None:
        bgp_local_asn_p = dict(bgpLocalAsnP=dict(attributes=dict(asnPropagate=local_as_number_config, localAsn=local_as_number)))
        if local_as_number == 0:
            bgp_local_asn_p["bgpLocalAsnP"]["attributes"]["status"] = "deleted"
        child_configs.append(bgp_local_asn_p)

    # BGP Peer Prefix Policy is ony configurable on Infra BGP Peer Profile
    if bgp_peer_prefix_policy is not None:
        child_configs.append(dict(bgpRsPeerPfxPol=dict(attributes=dict(tnBgpPeerPfxPolName=bgp_peer_prefix_policy))))

    if route_control_profiles:
        child_classes.append("bgpRsPeerToProfile")
        for profile in route_control_profiles:
            if profile.get("l3out"):
                route_control_profile_dn = "uni/tn-{0}/out-{1}/prof-{2}".format(
                    profile.get("tenant"),
                    profile.get("l3out"),
                    profile.get("profile"),
                )
            else:
                route_control_profile_dn = "uni/tn-{0}/prof-{1}".format(profile.get("tenant"), profile.get("profile"))
            child_configs.append(
                dict(
                    bgpRsPeerToProfile=dict(
                        attributes=dict(
                            direction=profile.get("direction"),
                            tDn=route_control_profile_dn,
                        )
                    )
                )
            )

    bgp_peer_profile_dict = dict(
        aci_class=aci_class,
        aci_rn="infraPeerP-[{0}]".format(peer_ip) if bgp_infra_peer else "peerP-[{0}]".format(peer_ip),
        module_object=peer_ip,
        target_filter={"addr": peer_ip},
    )

    if interface_profile is None:
        subclass_3 = bgp_peer_profile_dict
        subclass_4 = None
        subclass_5 = None
    else:
        subclass_3 = dict(
            aci_class="l3extLIfP",
            aci_rn="lifp-{0}".format(interface_profile),
            module_object=interface_profile,
            target_filter={"name": interface_profile},
        )
        subclass_4 = dict(
            aci_class="l3extRsPathL3OutAtt",
            aci_rn="rspathL3OutAtt-[{0}]".format(path_dn),
            module_object=path_dn,
            target_filter={"tDn": path_dn},
        )
        subclass_5 = bgp_peer_profile_dict

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
        subclass_2=dict(
            aci_class="l3extLNodeP",
            aci_rn="lnodep-{0}".format(node_profile),
            module_object=node_profile,
            target_filter={"name": node_profile},
        ),
        subclass_3=subclass_3,
        subclass_4=subclass_4,
        subclass_5=subclass_5,
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        ctrl, ctrl_ext, peerCtrl, addrTCtrl, privateASctrl = None, None, None, None, None
        if bgp_controls:
            if transport_data_plane == "mpls":
                bgp_controls.append("segment-routing-disable")

            if "send-domain-path" in bgp_controls:
                ctrl_ext = "send-domain-path"
                bgp_controls.remove("send-domain-path")

            ctrl = ",".join(bgp_controls)

        if peer_controls:
            peerCtrl = ",".join(peer_controls)
        if address_type_controls:
            addrTCtrl = ",".join(address_type_controls)
        if private_asn_controls:
            privateASctrl = ",".join(private_asn_controls)

        class_config = dict(
            descr=description,
            addr=peer_ip,
            ctrl=ctrl,
            ctrlExt=ctrl_ext,
            peerCtrl=peerCtrl,
            addrTCtrl=addrTCtrl,
            privateASctrl=privateASctrl,
            ttl=ttl,
            weight=weight,
            adminSt=admin_state,
            allowedSelfAsCnt=allow_self_as_count,
            peerT=peer_type.replace("_", "-") if peer_type else None,
        )

        # Only add bgp_password if it is set to handle changed status properly because password is not part of existing config
        if bgp_password:
            class_config["password"] = bgp_password

        aci.payload(aci_class=aci_class, class_config=class_config, child_configs=child_configs)

        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
