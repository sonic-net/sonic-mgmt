#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Shreyas Srish <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_floating_svi
short_description: Manage Layer 3 Outside (L3Out) interfaces (l3ext:VirtualLIfP)
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
    - Pod ID to build the interface on.
    type: str
  node_id:
    description:
    - Node ID to build the interface on for Port-channels and single ports.
    type: str
  encap:
    description:
    - Encapsulation on the interface (e.g. "vlan-500")
    type: str
  encap_scope:
    description:
    - Encapsulation scope.
    choices: [ vrf, local ]
    type: str
  address:
    description:
    - IP address.
    type: str
    aliases: [ addr, ip_address ]
  mac_address:
    description:
    - The MAC address option of the interface.
    type: str
  link_local_address:
    description:
    - The link local address option of the interface.
    type: str
  mtu:
    description:
    - Interface MTU.
    type: str
  ipv6_dad:
    description:
    - IPv6 Duplicate Address Detection (DAD) feature.
    type: str
    choices: [ enabled, disabled]
  mode:
    description:
    - The mode option for ext-svi interface.
    type: str
    choices: [ regular, native, untagged ]
  dscp:
    description:
    - The target Differentiated Service (DSCP) value.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
    aliases: [ target_dscp ]
  external_bridge_group_profile:
    description:
    - The external bridge group profile.
    - Pass "" as the value to remove an existing external bridge group profile (See Examples).
    - This is only supported in APIC v5.0 and above.
    type: str
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
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(tenant), C(l3out), C(logical_node_profile) and C(logical_interface_profile) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l3out), M(cisco.aci.aci_l3out_logical_node_profile), M(cisco.aci.aci_l3out_logical_interface_profile) \
  modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_l3out_logical_node_profile
- module: cisco.aci.aci_l3out_logical_interface_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:VirtualLIfP)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Create a Floating SVI
  cisco.aci.aci_l3out_floating_svi:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    encap: vlan-1
    address: 23.45.67.90/24
    external_bridge_group_profile: bridge1
    state: present
  delegate_to: localhost

- name: Remove an external bridge group profile
  cisco.aci.aci_l3out_floating_svi:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    encap: vlan-1
    address: 23.45.67.90/24
    external_bridge_group_profile: ""
    state: present
  delegate_to: localhost

- name: Remove a Floating SVI
  cisco.aci.aci_l3out_floating_svi:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    encap: vlan-1
    state: absent
  delegate_to: localhost

- name: Query a Floating SVI
  cisco.aci.aci_l3out_floating_svi:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    node_id: 201
    encap: vlan-1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all the Floating SVIs under an interface profile
  cisco.aci.aci_l3out_floating_svi:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    state: query
  delegate_to: localhost
  register: query_results
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_contract_dscp_spec


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
        address=dict(type="str", aliases=["addr", "ip_address"]),
        link_local_address=dict(type="str"),
        mac_address=dict(type="str"),
        mtu=dict(type="str"),
        ipv6_dad=dict(type="str", choices=["enabled", "disabled"]),
        mode=dict(type="str", choices=["regular", "native", "untagged"]),
        encap=dict(type="str"),
        encap_scope=dict(type="str", choices=["vrf", "local"]),
        auto_state=dict(type="str", choices=["enabled", "disabled"]),
        external_bridge_group_profile=dict(type="str"),
        dscp=aci_contract_dscp_spec(direction="dscp"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["pod_id", "node_id", "encap", "address"]],
            ["state", "absent", ["pod_id", "node_id", "encap"]],
        ],
    )

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
    state = module.params.get("state")
    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    address = module.params.get("address")
    mtu = module.params.get("mtu")
    ipv6_dad = module.params.get("ipv6_dad")
    link_local_address = module.params.get("link_local_address")
    mac_address = module.params.get("mac_address")
    mode = module.params.get("mode")
    encap = module.params.get("encap")
    encap_scope = "ctx" if module.params.get("encap_scope") == "vrf" else module.params.get("encap_scope")
    auto_state = module.params.get("auto_state")
    external_bridge_group_profile = module.params.get("external_bridge_group_profile")

    aci = ACIModule(module)

    node_dn = None
    if pod_id and node_id:
        node_dn = "topology/pod-{0}/node-{1}".format(pod_id, node_id)

    child_classes = []
    if external_bridge_group_profile is not None:
        child_classes.append("l3extBdProfileCont")

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
            aci_class="l3extVirtualLIfP", aci_rn="vlifp-[{0}]-[{1}]".format(node_dn, encap), module_object=node_dn, target_filter={"nodeDn": node_dn}
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if external_bridge_group_profile is not None:
            if external_bridge_group_profile == "" and isinstance(aci.existing, list) and len(aci.existing) > 0:
                if aci.existing[0].get("l3extVirtualLIfP", {}).get("children") is not None:
                    child_configs.append(
                        dict(
                            l3extBdProfileCont=dict(
                                attributes=dict(status="deleted"),
                            ),
                        )
                    )
            elif external_bridge_group_profile != "":
                child_configs.append(
                    dict(
                        l3extBdProfileCont=dict(
                            attributes=dict(),
                            children=[
                                dict(
                                    l3extRsBdProfile=dict(
                                        attributes=dict(
                                            tDn="uni/tn-{0}/bdprofile-{1}".format(tenant, external_bridge_group_profile),
                                        ),
                                    )
                                )
                            ],
                        )
                    )
                )

        aci.payload(
            aci_class="l3extVirtualLIfP",
            class_config=dict(
                addr=address,
                ipv6Dad=ipv6_dad,
                mtu=mtu,
                ifInstT="ext-svi",
                mode=mode,
                encap=encap,
                encapScope=encap_scope,
                autostate=auto_state,
                llAddr=link_local_address,
                mac=mac_address,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="l3extVirtualLIfP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
