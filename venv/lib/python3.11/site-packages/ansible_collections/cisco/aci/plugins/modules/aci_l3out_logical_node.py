#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Marcel Zehnder (@maercu)
# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_logical_node
short_description: Manage Layer 3 Outside (L3Out) logical node profile nodes (l3ext:RsNodeL3OutAtt)
description:
- Bind nodes to node profiles on Cisco ACI fabrics.
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
  pod_id:
    description:
    - Existing podId.
    type: int
  node_id:
    description:
    - Existing nodeId.
    type: int
  router_id:
    description:
    - Router ID in dotted decimal notation.
    type: str
  router_id_as_loopback:
    description:
    - Configure the router ID as a loopback IP.
    type: str
    choices: [ 'yes', 'no' ]
    default: 'yes'
  loopback_address:
    description:
    - The loopback IP address.
    - The BGP-EVPN loopback IP address for Infra SR-MPLS L3Outs.
    - A configured loopback address can be removed by passing an empty string (see Examples).
    type: str
    aliases: [ loopback ]
  mpls_transport_loopback_address:
    description:
    - The MPLS transport loopback IP address for Infra SR-MPLS L3Outs.
    type: str
    aliases: [ mpls_transport_loopback ]
  sid:
    description:
    - The Segment ID (SID) Index for Infra SR-MPLS L3Outs.
    type: str
    aliases: [ segment_id ]
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
  description: More information about the internal APIC classes B(l3ext:RsNodeL3OutAtt)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Marcel Zehnder (@maercu)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new node to a node profile
  cisco.aci.aci_l3out_logical_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    pod_id: 1
    node_id: 111
    router_id: 111.111.111.111
    loopback_address: 111.111.111.112
    state: present
  delegate_to: localhost

- name: Add a node to a infra SR-MPLS l3out node profile
  cisco.aci.aci_l3out_logical_node: &aci_infra_node_profile_node
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: infra
    l3out: ansible_infra_sr_mpls_l3out
    node_profile: ansible_infra_sr_mpls_l3out_node_profile
    pod_id: 1
    node_id: 113
    router_id_as_loopback: 'no'
    loopback_address: 50.0.0.1
    mpls_transport_loopback_address: 51.0.0.1
    sid: 500
  delegate_to: localhost

- name: Remove a loopback address from a node in node profile
  cisco.aci.aci_l3out_logical_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    pod_id: 1
    node_id: 111
    loopback_address: ""
  delegate_to: localhost

- name: Delete a node from a node profile
  cisco.aci.aci_l3out_logical_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    pod_id: 1
    node_id: 111
    state: absent
  delegate_to: localhost

- name: Query a node
  cisco.aci.aci_l3out_logical_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    pod_id: 1
    node_id: 111
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all nodes
  cisco.aci.aci_l3out_logical_node:
    host: apic
    username: admin
    password: SomeSecretPassword
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        node_profile=dict(type="str", aliases=["node_profile_name", "logical_node"]),
        pod_id=dict(type="int"),
        node_id=dict(type="int"),
        router_id=dict(type="str"),
        router_id_as_loopback=dict(type="str", default="yes", choices=["yes", "no"]),
        loopback_address=dict(type="str", aliases=["loopback"]),
        mpls_transport_loopback_address=dict(type="str", aliases=["mpls_transport_loopback"]),
        sid=dict(type="str", aliases=["segment_id"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "l3out", "node_profile", "pod_id", "node_id"]],
            ["state", "present", ["tenant", "l3out", "node_profile", "pod_id", "node_id"]],
        ],
        required_by={"mpls_transport_loopback_address": "loopback_address"},
        required_together=[("mpls_transport_loopback_address", "sid")],
    )

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    router_id = module.params.get("router_id")
    router_id_as_loopback = module.params.get("router_id_as_loopback")
    loopback_address = module.params.get("loopback_address")
    mpls_transport_loopback_address = module.params.get("mpls_transport_loopback_address")
    sid = module.params.get("sid")
    state = module.params.get("state")

    tdn = None
    if pod_id is not None and node_id is not None:
        tdn = "topology/pod-{0}/node-{1}".format(pod_id, node_id)

    aci = ACIModule(module)

    child_classes = ["l3extLoopBackIfP"]

    if mpls_transport_loopback_address is not None:
        child_classes.append("mplsNodeSidP")

    child_configs = []

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
            aci_class="l3extRsNodeL3OutAtt",
            aci_rn="rsnodeL3OutAtt-[{0}]".format(tdn),
            module_object=tdn,
            target_filter={"name": tdn},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        if loopback_address is not None:
            if loopback_address == "" and isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("l3extRsNodeL3OutAtt", {}).get("children", []):
                    previous_loopback_address = child.get("l3extLoopBackIfP", {}).get("attributes", {}).get("addr")
                    child_configs.append(dict(l3extLoopBackIfP=dict(attributes=dict(addr=previous_loopback_address, status="deleted"))))
            elif loopback_address:
                loopback_address_config = dict(l3extLoopBackIfP=dict(attributes=dict(addr=loopback_address), children=[]))
                if mpls_transport_loopback_address:
                    loopback_address_config["l3extLoopBackIfP"]["children"].append(
                        dict(mplsNodeSidP=dict(attributes=dict(loopbackAddr=mpls_transport_loopback_address, sidoffset=sid)))
                    )
                child_configs.append(loopback_address_config)

        aci.payload(
            aci_class="l3extRsNodeL3OutAtt",
            class_config=dict(rtrId=router_id, rtrIdLoopBack=router_id_as_loopback, tDn=tdn),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="l3extRsNodeL3OutAtt")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
