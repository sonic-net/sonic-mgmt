#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l2out_logical_interface_path
short_description: Manage Layer 2 Outside (L2Out) logical interface path (l2ext:RsPathL2OutAtt)
description:
- Manage interface path entry of L2 outside node (BD extension) on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l2out:
    description:
    - Name of an existing L2Out.
    type: str
    aliases: [ l2out_name ]
  node_profile:
    description:
    - Name of the node profile.
    type: str
    aliases: [ node_profile_name, logical_node ]
  interface_profile:
    description:
    - Name of the interface profile.
    type: str
    aliases: [ name, interface_profile_name, logical_interface ]
  interface_type:
    description:
    - The type of interface for the static EPG deployment.
    type: str
    choices: [ switch_port, port_channel, vpc ]
    default: switch_port
  pod_id:
    description:
    - The pod number part of the tDn.
    - C(pod_id) is usually an integer below C(10).
    type: int
    aliases: [ pod, pod_number ]
  leaves:
    description:
    - The switch ID(s) that the C(interface) belongs to.
    - When C(interface_type) is C(switch_port) or C(port_channel), then C(leaves) is a string of the leaf ID.
    - When C(interface_type) is C(vpc), then C(leaves) is a list with both leaf IDs.
    - The C(leaves) value is usually something like '101' or '101-102' depending on C(connection_type).
    type: list
    elements: str
    aliases: [ leafs, nodes, paths, switches ]
  interface:
    description:
    - The C(interface) string value part of the tDn.
    - Usually a policy group like C(test-IntPolGrp) or an interface of the following format C(1/7) depending on C(interface_type).
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

seealso:
- module: cisco.aci.aci_l2out
- module: cisco.aci.aci_l2out_logical_node_profile
- module: cisco.aci.aci_l2out_logical_interface_profile
- module: cisco.aci.aci_l2out_extepg
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l2ext:RsPathL2OutAtt).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Oleksandr Kreshchenko (@alexkross)
"""

EXAMPLES = r"""
- name: Add new path to interface profile
  cisco.aci.aci_l2out_logical_interface_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l2out: my_l2out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    leaves: 101-102
    interface: L2o1
    state: present
  delegate_to: localhost

- name: Delete path to interface profile
  cisco.aci.aci_l2out_logical_interface_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l2out: my_l2out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    leaves: 101-102
    interface: L2o1
    state: absent
  delegate_to: localhost

- name: Query a path to interface profile
  cisco.aci.aci_l2out_logical_interface_path:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l2out: my_l2out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    pod_id: 1
    leaves: 101-102
    interface: L2o1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all paths to interface profiles
  cisco.aci.aci_l2out_logical_interface_path:
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


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec

INTERFACE_TYPE_MAPPING = dict(
    switch_port="topology/pod-{pod_id}/paths-{leaves}/pathep-[eth{interface}]",
    port_channel="topology/pod-{pod_id}/paths-{leaves}/pathep-[{interface}]",
    vpc="topology/pod-{pod_id}/protpaths-{leaves}/pathep-[{interface}]",
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(  # See comments in aci_static_binding_to_epg module.
        tenant=dict(type="str", aliases=["tenant_name"]),
        l2out=dict(type="str", aliases=["l2out_name"]),
        node_profile=dict(type="str", aliases=["node_profile_name", "logical_node"]),
        interface_profile=dict(type="str", aliases=["name", "interface_profile_name", "logical_interface"]),
        interface_type=dict(type="str", default="switch_port", choices=["switch_port", "port_channel", "vpc"]),
        pod_id=dict(type="int", aliases=["pod", "pod_number"]),
        leaves=dict(type="list", elements="str", aliases=["leafs", "nodes", "paths", "switches"]),
        interface=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "l2out", "node_profile", "interface_profile", "pod_id", "leaves", "interface"]],
            ["state", "present", ["tenant", "l2out", "node_profile", "interface_profile", "pod_id", "leaves", "interface"]],
        ],
    )

    tenant = module.params.get("tenant")
    l2out = module.params.get("l2out")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
    interface_type = module.params.get("interface_type")
    pod_id = module.params.get("pod_id")
    leaves = module.params.get("leaves")
    if leaves is not None:  # Process leaves, and support dash-delimited leaves
        leaves = []
        for leaf in module.params.get("leaves"):  # Users are likely to use integers for leaf IDs, which would raise an exception when using the join method
            leaves.extend(str(leaf).split("-"))
        if len(leaves) == 1:
            if interface_type == "vpc":
                module.fail_json(msg='A interface_type of "vpc" requires 2 leaves')
            leaves = leaves[0]
        elif len(leaves) == 2:
            if interface_type != "vpc":
                module.fail_json(msg='The interface_types "switch_port" and "port_channel" do not support using multiple leaves for a single binding')
            leaves = "-".join(leaves)
        else:
            module.fail_json(msg='The "leaves" parameter must not have more than 2 entries')
    interface = module.params.get("interface")
    state = module.params.get("state")

    path = INTERFACE_TYPE_MAPPING[interface_type].format(pod_id=pod_id, leaves=leaves, interface=interface)
    if not pod_id or not leaves or not interface:
        path = None

    path_target_filter = {}
    if any((pod_id, leaves, interface)):
        path_target_filter = {"tDn": path}

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="l2extOut",
            aci_rn="l2out-{0}".format(l2out),
            module_object=l2out,
            target_filter={"name": l2out},
        ),
        subclass_2=dict(
            aci_class="l2extLNodeP",
            aci_rn="lnodep-{0}".format(node_profile),
            module_object=node_profile,
            target_filter={"name": node_profile},
        ),
        subclass_3=dict(
            aci_class="l2extLIfP",
            aci_rn="lifp-{0}".format(interface_profile),
            module_object=interface_profile,
            target_filter={"name": interface_profile},
        ),
        subclass_4=dict(
            aci_class="l2extRsPathL2OutAtt",
            aci_rn="rspathL2OutAtt-[{0}]".format(path),
            # rspathL2OutAtt-[topology/pod-1/protpaths-101-102/pathep-[L2o2_n7]]
            module_object=path,
            target_filter=path_target_filter,
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="l2extRsPathL2OutAtt",
            class_config=dict(tDn=path),
        )

        aci.get_diff(aci_class="l2extRsPathL2OutAtt")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
