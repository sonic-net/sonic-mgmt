#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_logical_interface_profile
short_description: Manage Layer 3 Outside (L3Out) logical interface profiles (l3ext:LIfP)
description:
- Manage L3Out interface profiles on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - The name of an existing L3Out.
    type: str
    aliases: [ l3out_name ]
  node_profile:
    description:
    - The name of the node profile.
    type: str
    aliases: [ node_profile_name, logical_node ]
  interface_profile:
    description:
    - The name of the logical interface profile.
    type: str
    aliases: [ name, interface_profile_name, logical_interface ]
  nd_policy:
    description:
    - The name of the neighbor discovery interface policy.
    type: str
  egress_dpp_policy:
    description:
    - The name of the egress data plane policing policy.
    type: str
  ingress_dpp_policy:
    description:
    - The name of the ingress data plane policing policy.
    type: str
  qos_priority:
    description:
    - The QoS priority class ID.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ level1, level2, level3, level4, level5, level6, unspecified ]
    aliases: [ priority, prio ]
  qos_custom_policy:
    description:
    - The name of the QoS custom policy.
    type: str
    aliases: [ qos_custom_policy_name ]
  pim_v4_interface_profile:
    description:
    - The PIM IPv4 interface profile.
    type: dict
    suboptions:
      tenant:
        description:
        - The name of the tenant to which the PIM IPv4 interface policy belongs.
        type: str
        aliases: [ tenant_name ]
      pim:
        description:
        - The name of the PIM IPv4 interface policy.
        type: str
        aliases: [ pim_interface_policy, name ]
    aliases: [ pim_v4 ]
  pim_v6_interface_profile:
    description:
    - The PIM IPv6 interface profile.
    type: dict
    suboptions:
      tenant:
        description:
        - The name of the tenant to which the PIM IPv6 interface policy belongs.
        type: str
        aliases: [ tenant_name ]
      pim:
        description:
        - The name of the PIM IPv6 interface policy.
        type: str
        aliases: [ pim_interface_policy, name ]
    aliases: [ pim_v6 ]
  igmp_interface_profile:
    description:
    - The IGMP interface profile.
    type: dict
    suboptions:
      tenant:
        description:
        - The name of the tenant to which the IGMP interface policy belongs.
        type: str
        aliases: [ tenant_name ]
      igmp:
        description:
        - The name of the IGMP interface policy.
        type: str
        aliases: [ igmp_interface_policy, name ]
    aliases: [ igmp ]
  description:
    description:
    - The description for the logical interface profile.
    type: str
    aliases: [ descr ]
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
- cisco.aci.owner

notes:
- The I(tenant), I(l3out) and I(node_profile) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l3out) and M(cisco.aci.aci_l3out_logical_node_profile) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_l3out_logical_node_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:LIfP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Marcel Zehnder (@maercu)
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a new interface profile
  cisco.aci.aci_l3out_logical_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    state: present
  delegate_to: localhost

- name: Query an interface profile
  cisco.aci.aci_l3out_logical_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all interface profiles
  cisco.aci.aci_l3out_logical_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete an interface profile
  cisco.aci.aci_l3out_logical_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
    aci_owner_spec,
    pim_interface_profile_spec,
    igmp_interface_profile_spec,
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        node_profile=dict(type="str", aliases=["node_profile_name", "logical_node"]),
        interface_profile=dict(type="str", aliases=["name", "interface_profile_name", "logical_interface"]),
        nd_policy=dict(type="str"),
        egress_dpp_policy=dict(type="str"),
        ingress_dpp_policy=dict(type="str"),
        qos_priority=dict(type="str", choices=["level1", "level2", "level3", "level4", "level5", "level6", "unspecified"], aliases=["priority", "prio"]),
        qos_custom_policy=dict(type="str", aliases=["qos_custom_policy_name"]),
        pim_v4_interface_profile=dict(type="dict", options=pim_interface_profile_spec(), aliases=["pim_v4"]),
        pim_v6_interface_profile=dict(type="dict", options=pim_interface_profile_spec(), aliases=["pim_v6"]),
        igmp_interface_profile=dict(type="dict", options=igmp_interface_profile_spec(), aliases=["igmp"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        description=dict(type="str", aliases=["descr"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "l3out", "node_profile", "interface_profile"]],
            ["state", "present", ["tenant", "l3out", "node_profile", "interface_profile"]],
        ],
    )

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
    nd_policy = module.params.get("nd_policy")
    egress_dpp_policy = module.params.get("egress_dpp_policy")
    ingress_dpp_policy = module.params.get("ingress_dpp_policy")
    qos_priority = module.params.get("qos_priority")
    qos_custom_policy = module.params.get("qos_custom_policy")
    description = module.params.get("description")
    state = module.params.get("state")

    aci = ACIModule(module)

    extra_child_classes = dict(
        pimIPV6IfP=dict(rs_class="pimRsV6IfPol", attribute_input=module.params.get("pim_v6_interface_profile")),
        pimIfP=dict(rs_class="pimRsIfPol", attribute_input=module.params.get("pim_v4_interface_profile")),
        igmpIfP=dict(rs_class="igmpRsIfPol", attribute_input=module.params.get("igmp_interface_profile")),
    )

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
        child_classes=list(extra_child_classes.keys()) + ["l3extRsEgressQosDppPol", "l3extRsIngressQosDppPol", "l3extRsLIfPCustQosPol", "l3extRsNdIfPol"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = [
            dict(l3extRsNdIfPol=dict(attributes=dict(tnNdIfPolName=nd_policy))),
            dict(l3extRsIngressQosDppPol=dict(attributes=dict(tnQosDppPolName=ingress_dpp_policy))),
            dict(l3extRsEgressQosDppPol=dict(attributes=dict(tnQosDppPolName=egress_dpp_policy))),
            dict(l3extRsLIfPCustQosPol=dict(attributes=dict(tnQosCustomPolName=qos_custom_policy))),
        ]
        for class_name, attribute in extra_child_classes.items():
            attribute_input = attribute.get("attribute_input")
            if attribute_input is not None:
                rs_class = attribute.get("rs_class")
                if all(value is None for value in attribute_input.values()) and isinstance(aci.existing, list) and len(aci.existing) > 0:
                    for child in aci.existing[0].get("l3extLIfP", {}).get("children", {}):
                        if child.get(class_name):
                            child_configs.append(
                                {
                                    class_name: dict(
                                        attributes=dict(status="deleted"),
                                    ),
                                }
                            )
                elif all(value is not None for value in attribute_input.values()):
                    if rs_class in ["pimRsV6IfPol", "pimRsIfPol"]:
                        child_configs.append(
                            {
                                class_name: dict(
                                    attributes={},
                                    children=[
                                        {
                                            rs_class: dict(
                                                attributes=dict(
                                                    tDn="uni/tn-{0}/pimifpol-{1}".format(attribute_input.get("tenant"), attribute_input.get("pim"))
                                                )
                                            )
                                        },
                                    ],
                                )
                            }
                        )
                    elif rs_class == "igmpRsIfPol":
                        child_configs.append(
                            {
                                class_name: dict(
                                    attributes={},
                                    children=[
                                        {
                                            rs_class: dict(
                                                attributes=dict(
                                                    tDn="uni/tn-{0}/igmpIfPol-{1}".format(attribute_input.get("tenant"), attribute_input.get("igmp"))
                                                )
                                            )
                                        },
                                    ],
                                )
                            }
                        )

        aci.payload(
            aci_class="l3extLIfP",
            class_config=dict(
                name=interface_profile,
                prio=qos_priority,
                descr=description,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="l3extLIfP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
