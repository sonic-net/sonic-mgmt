#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Anvitha Jain(@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_l3out_logical_interface_vpc_member
short_description: Manage Member Node objects (l3ext:Member)
description:
- Manage Member Node objects (l3ext:Member)
options:
  description:
    description:
    - The description for the logical interface VPC member.
    type: str
    aliases: [ descr ]
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
    - Pod to of the interface.
    type: str
  node_id:
    description:
    - Hyphen separated pair of nodes (e.g. "201-202")
    type: str
  path_ep:
    description:
    - vPC Interface Policy Group name
    type: str
  path_dn:
    description:
    - DN of existing path endpoint (fabricPathEp).
    type: str
  side:
    description:
    - Provides the side of member.
    type: str
    choices: [ A, B ]
  address:
    description:
    - IP address.
    type: str
    aliases: [ addr, ip_address]
  ipv6_dad:
    description:
    - IPv6 DAD feature.
    type: str
    choices: [ enabled, disabled]
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

notes:
- The L3Out vPC inteface used must exist before using this module in your playbook.
  The M(cisco.aci.aci_l3out_logical_interface_profile) module can be used for this.
seealso:
- module: cisco.aci.aci_l3out_logical_interface_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:Member).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Anvitha Jain (@anvitha-jain)
- Marcel Zehnder (@maercu)
"""

EXAMPLES = r"""
- name: Create a VPC member based on the path_dn
  cisco.aci.aci_l3out_logical_interface_vpc_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    l3out: l3out
    node_profile: nodeName
    interface_profile: interfaceName
    path_dn: topology/pod-1/protpaths-101-102/pathep-[policy_group_name]
    side: A
    state: present
  delegate_to: localhost

- name: Create a VPC member based pod, node and path
  cisco.aci.aci_l3out_logical_interface_vpc_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    l3out: l3out
    node_profile: nodeName
    interface_profile: interfaceName
    pod_id: 1
    node_id: 101-102
    path_ep: policy_group_name
    side: A
    address: 192.168.1.252/24
    state: present
  delegate_to: localhost

- name: Delete a VPC member
  cisco.aci.aci_l3out_logical_interface_vpc_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    l3out: l3out
    node_profile: nodeName
    interface_profile: interfaceName
    path_dn: topology/pod-1/protpaths-101-102/pathep-[policy_group_name]
    side: A
    state: absent
  delegate_to: localhost

- name: Query all VPC members
  cisco.aci.aci_l3out_logical_interface_vpc_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific VPC member under l3out
  cisco.aci.aci_l3out_logical_interface_vpc_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    l3out: l3out
    node_profile: nodeName
    interface_profile: interfaceName
    path_dn: topology/pod-1/protpaths-101-102/pathep-[policy_group_name]
    side: A
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
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        l3out=dict(type="str", aliases=["l3out_name"]),  # Not required for querying all objects
        node_profile=dict(type="str", aliases=["node_profile_name", "logical_node"]),  # Not required for querying all objects
        interface_profile=dict(type="str", aliases=["interface_profile_name", "logical_interface"]),
        path_dn=dict(type="str"),
        pod_id=dict(type="str"),
        node_id=dict(type="str"),
        path_ep=dict(type="str"),
        side=dict(type="str", choices=["A", "B"]),
        address=dict(type="str", aliases=["addr", "ip_address"]),
        ipv6_dad=dict(type="str", choices=["enabled", "disabled"]),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["side", "interface_profile", "node_profile", "l3out", "tenant"]],
            ["state", "absent", ["side", "interface_profile", "node_profile", "l3out", "tenant"]],
        ],
        mutually_exclusive=[
            ["path_dn", "pod_id"],
            ["path_dn", "node_id"],
            ["path_dn", "path_ep"],
        ],
        required_together=[
            ["pod_id", "node_id", "path_ep"],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    path_ep = module.params.get("path_ep")
    path_dn = module.params.get("path_dn")
    side = module.params.get("side")
    address = module.params.get("address")
    ipv6_dad = module.params.get("ipv6_dad")
    description = module.params.get("description")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    if not path_dn:
        if pod_id and node_id and path_ep:
            path_dn = "topology/pod-{0}/protpaths-{1}/pathep-[{2}]".format(pod_id, node_id, path_ep)
        else:
            path_dn = None

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
            target_filter={"name": path_dn},
        ),
        subclass_5=dict(
            aci_class="l3extMember",
            aci_rn="mem-{0}".format(side),
            module_object=side,
            target_filter={"side": side},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="l3extMember",
            class_config=dict(
                side=side,
                addr=address,
                ipv6Dad=ipv6_dad,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="l3extMember")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
