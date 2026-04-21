#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Tim Cragg (@timcragg)
# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_interface
short_description: Manage Layer 3 Outside (L3Out) interfaces (l3ext:RsPathL3OutAtt)
description:
- Manage L3Out interfaces on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
    required: true
  l3out:
    description:
    - Name of an existing L3Out.
    type: str
    aliases: [ l3out_name ]
    required: true
  node_profile:
    description:
    - Name of the node profile.
    type: str
    aliases: [ node_profile_name, logical_node ]
    required: true
  interface_profile:
    description:
    - Name of the interface profile.
    type: str
    aliases: [ interface_profile_name, logical_interface ]
    required: true
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
    - Path to interface.
    - Interface Policy Group name for Port-channels and vPCs.
    - Port number for single ports (e.g. "eth1/12").
    type: str
  encap:
    description:
    - The encapsulation on the interface (e.g. "vlan-500").
    type: str
  encap_scope:
    description:
    - The scope of the encapsulation on the interface.
    type: str
    choices: [ vrf, local ]
  address:
    description:
    - IP address.
    type: str
    aliases: [ addr, ip_address]
  mtu:
    description:
    - Interface MTU.
    type: str
  ipv6_dad:
    description:
    - IPv6 DAD feature.
    type: str
    choices: [ enabled, disabled]
  interface_type:
    description:
    - Type of interface to build.
    type: str
    choices: [ l3-port, sub-interface, ext-svi ]
  mode:
    description:
    - Interface mode, only used if instance_type is ext-svi.
    type: str
    choices: [ regular, native, untagged ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  auto_state:
    description:
    - SVI auto state.
    type: str
    choices: [ enabled, disabled ]
  description:
    description:
    - The description of the interface.
    type: str
    aliases: [ descr]
  mac:
    description:
    - The MAC address of the interface.
    type: str
    aliases: [ mac_address ]
  micro_bfd:
    description:
    - Enable micro BFD on the interface.
    - Micro BFD should only be configured on Infra SR-MPLS L3Outs Direct Port Channel Interfaces.
    type: bool
  micro_bfd_destination:
    description:
    - The micro BFD destination address of the interface.
    type: str
    aliases: [ micro_bfd_address, micro_bfd_destination_address ]
  micro_bfd_timer:
    description:
    - The micro BFD start timer in seconds.
    - The APIC defaults to C(0) when unset during creation.
    type: int
    aliases: [ micro_bfd_start_timer, micro_bfd_start ]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(tenant), C(l3out), C(node_profile) and the C(interface_profile) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l3out), M(cisco.aci.aci_l3out_logical_node_profile) and
  M(cisco.aci.aci_l3out_logical_interface_profile) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_l3out_logical_node_profile
- module: cisco.aci.aci_l3out_logical_interface_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:RsPathL3OutAtt)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new routed interface
  cisco.aci.aci_l3out_interface:
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
    interface_type: l3-port
    address: 192.168.10.1/27
    state: present
  delegate_to: localhost

- name: Add a new SVI vPC
  cisco.aci.aci_l3out_interface:
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
    interface_type: ext-svi
    encap: vlan-800
    mode: regular
    state: present
  delegate_to: localhost

- name: Add direct port channel interface in the infra SR-MPLS l3out interface profile with micro BFD enabled
  aci_l3out_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: infra
    l3out: ansible_infra_sr_mpls_l3out
    interface_profile: ansible_infra_sr_mpls_l3out_interface_profile
    pod_id: 1
    node_id: 101
    path_ep: pc_ansible_test
    interface_type: l3-port
    addr: 192.168.90.1/24
    micro_bfd: true
    micro_bfd_destination: 192.168.90.2
    micro_bfd_timer: 75
    state: present
  delegate_to: localhost

- name: Delete an interface
  cisco.aci.aci_l3out_interface:
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
    state: absent
  delegate_to: localhost

- name: Query an interface
  cisco.aci.aci_l3out_interface:
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
    state: query
  delegate_to: localhost
  register: query_result
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
        tenant=dict(type="str", aliases=["tenant_name"], required=True),
        l3out=dict(type="str", aliases=["l3out_name"], required=True),
        node_profile=dict(type="str", aliases=["node_profile_name", "logical_node"], required=True),
        interface_profile=dict(type="str", aliases=["interface_profile_name", "logical_interface"], required=True),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        pod_id=dict(type="str"),
        node_id=dict(type="str"),
        path_ep=dict(type="str"),
        address=dict(type="str", aliases=["addr", "ip_address"]),
        mtu=dict(type="str"),
        ipv6_dad=dict(type="str", choices=["enabled", "disabled"]),
        interface_type=dict(type="str", choices=["l3-port", "sub-interface", "ext-svi"]),
        mode=dict(type="str", choices=["regular", "native", "untagged"]),
        encap=dict(type="str"),
        encap_scope=dict(type="str", choices=["vrf", "local"]),
        auto_state=dict(type="str", choices=["enabled", "disabled"]),
        description=dict(type="str", aliases=["descr"]),
        mac=dict(type="str", aliases=["mac_address"]),
        micro_bfd=dict(type="bool"),
        micro_bfd_destination=dict(type="str", aliases=["micro_bfd_address", "micro_bfd_destination_address"]),
        micro_bfd_timer=dict(type="int", aliases=["micro_bfd_start_timer", "micro_bfd_start"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["interface_type", "pod_id", "node_id", "path_ep"]],
            ["state", "absent", ["pod_id", "node_id", "path_ep"]],
            ["micro_bfd", True, ["micro_bfd_destination"]],
        ],
        required_by={"micro_bfd_timer": "micro_bfd", "micro_bfd_destination": "micro_bfd"},
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
    state = module.params.get("state")
    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    path_ep = module.params.get("path_ep")
    address = module.params.get("address")
    mtu = module.params.get("mtu")
    ipv6_dad = module.params.get("ipv6_dad")
    interface_type = module.params.get("interface_type")
    mode = module.params.get("mode")
    encap = module.params.get("encap")
    encap_scope = module.params.get("encap_scope")
    auto_state = module.params.get("auto_state")
    description = module.params.get("description")
    mac = module.params.get("mac")
    micro_bfd = aci.boolean(module.params.get("micro_bfd"))
    micro_bfd_destination = module.params.get("micro_bfd_destination")
    micro_bfd_timer = module.params.get("micro_bfd_timer")

    if node_id and "-" in node_id:
        path_type = "protpaths"
    else:
        path_type = "paths"

    path_dn = None
    if pod_id and node_id and path_ep:
        path_dn = "topology/pod-{0}/{1}-{2}/pathep-[{3}]".format(pod_id, path_type, node_id, path_ep)

    child_classes = []
    child_configs = []
    if micro_bfd is not None:
        child_classes.append("bfdMicroBfdP")
        child_configs.append(dict(bfdMicroBfdP=dict(attributes=dict(adminState=micro_bfd, dst=micro_bfd_destination, stTm=micro_bfd_timer))))

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
        subclass_3=dict(
            aci_class="l3extLIfP",
            aci_rn="lifp-{0}".format(interface_profile),
            module_object=interface_profile,
            target_filter={"name": interface_profile},
        ),
        subclass_4=dict(
            aci_class="l3extRsPathL3OutAtt",
            aci_rn="rspathL3OutAtt-[{0}]".format(path_dn),
            module_object=path_dn,
            target_filter={"tDn": path_dn},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="l3extRsPathL3OutAtt",
            class_config=dict(
                tDn=path_dn,
                addr=address,
                ipv6Dad=ipv6_dad,
                mtu=mtu,
                ifInstT=interface_type,
                mode=mode,
                encap=encap,
                encapScope="ctx" if encap_scope == "vrf" else encap_scope,
                autostate=auto_state,
                descr=description,
                mac=mac,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="l3extRsPathL3OutAtt")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
