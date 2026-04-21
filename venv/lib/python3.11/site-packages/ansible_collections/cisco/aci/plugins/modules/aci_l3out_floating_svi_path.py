#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Shreyas Srish <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_floating_svi_path
short_description: Manage Layer 3 Outside (L3Out) Floating SVI Path Attributes (l3ext:RsDynPathAtt)
description:
- Manages L3Out Floating SVI path attributes on Cisco ACI fabrics.
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
    required: true
  node_id:
    description:
    - Node to build the interface on for Port-channels and single ports.
    type: str
    required: true
  encap:
    description:
    - Encapsulation on the interface (e.g. "vlan-500")
    type: str
    required: true
  domain:
    description:
    - This option allows virtual machines to send frames with a mac address.
    type: str
  domain_type:
    description:
    - The domain type of the path.
    - The physical domain type is only supported in APIC v5.0 and above.
    type: str
    choices: [ physical, vmware ]
  access_encap:
    description:
    - The port encapsulation option.
    type: str
  floating_ip:
    description:
    - The floating IP address.
    type: str
    aliases: [ floating_address ]
  forged_transmit:
    description:
    - This option allows virtual machines to send frames with a mac address.
    - This is only supported in APIC v5.0 and above.
    type: str
    choices: [ enabled, disabled ]
  mac_change:
    description:
    - The status of the mac address change support for port groups in an external VMM controller.
    - This is only supported in APIC v5.0 and above.
    type: str
    choices: [ enabled, disabled ]
  promiscuous_mode:
    description:
    - The status of promiscuous mode for port groups in an external VMM controller.
    - This is only supported in APIC v5.0 and above.
    type: str
    choices: [ enabled, disabled ]
  enhanced_lag_policy:
    description:
    - The enhanced lag policy of the path.
    - Pass "" as the value to remove an existing enhanced lag policy (See Examples).
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

notes:
- The C(tenant), C(l3out), C(logical_node_profile), C(logical_interface_profile) and C(floating_svi) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l3out), M(cisco.aci.aci_l3out_logical_node_profile), M(cisco.aci.aci_l3out_logical_interface_profile) and
  M(cisco.aci.aci_l3out_floating_svi) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_l3out_logical_node_profile
- module: cisco.aci.aci_l3out_logical_interface_profile
- module: cisco.aci.aci_l3out_floating_svi
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:RsDynPathAtt))
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Create a Floating SVI path attribute
  cisco.aci.aci_l3out_floating_svi_path:
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
    floating_ip: 23.45.67.90/24
    domain_type: virtual
    domain: anstest
    enhanced_lag_policy: enhanced
    state: present
  delegate_to: localhost

- name: Remove enhanced lag policy from the path
  cisco.aci.aci_l3out_floating_svi_path:
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
    floating_ip: 23.45.67.90/24
    domain_type: virtual
    domain: anstest
    enhanced_lag_policy: ""
    state: present
  delegate_to: localhost

- name: Remove a Floating SVI path attribute
  cisco.aci.aci_l3out_floating_svi_path:
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
    domain_type: virtual
    domain: anstest
    state: absent
  delegate_to: localhost

- name: Query a Floating SVI path attribute
  cisco.aci.aci_l3out_floating_svi_path:
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
    domain_type: virtual
    domain: anstest
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all the Floating SVI path attributes
  cisco.aci.aci_l3out_floating_svi_path:
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
        pod_id=dict(type="str", required=True),
        node_id=dict(type="str", required=True),
        encap=dict(type="str", required=True),
        floating_ip=dict(type="str", aliases=["floating_address"]),
        forged_transmit=dict(type="str", choices=["enabled", "disabled"]),
        mac_change=dict(type="str", choices=["enabled", "disabled"]),
        promiscuous_mode=dict(type="str", choices=["enabled", "disabled"]),
        domain_type=dict(type="str", choices=["physical", "vmware"]),
        domain=dict(type="str"),
        enhanced_lag_policy=dict(type="str"),
        access_encap=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["domain_type", "domain", "floating_ip"]],
            ["state", "absent", ["domain_type", "domain"]],
        ],
    )

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
    state = module.params.get("state")
    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    floating_ip = module.params.get("floating_ip")
    encap = module.params.get("encap")
    forged_transmit = module.params.get("forged_transmit").capitalize() if module.params.get("forged_transmit") else None
    mac_change = module.params.get("mac_change").capitalize() if module.params.get("mac_change") else None
    promiscuous_mode = module.params.get("promiscuous_mode").capitalize() if module.params.get("promiscuous_mode") else None
    domain_type = module.params.get("domain_type")
    domain = module.params.get("domain")
    enhanced_lag_policy = module.params.get("enhanced_lag_policy")
    access_encap = module.params.get("access_encap")

    aci = ACIModule(module)

    node_dn = "topology/pod-{0}/node-{1}".format(pod_id, node_id)

    tDn = None
    if domain_type == "physical":
        tDn = "uni/phys-{0}".format(domain)
    elif domain_type == "vmware":
        tDn = "uni/vmmp-VMware/dom-{0}".format(domain)

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
        subclass_5=dict(
            aci_class="l3extRsDynPathAtt",
            aci_rn="rsdynPathAtt-[{0}]".format(tDn),
            module_object=tDn,
            target_filter={"tDn": tDn},
        ),
        child_classes=["l3extVirtualLIfPLagPolAtt"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if enhanced_lag_policy is not None and domain_type == "vmware":
            existing_enhanced_lag_policy = ""
            if isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("l3extRsDynPathAtt", {}).get("children", {}):
                    if child.get("l3extVirtualLIfPLagPolAtt"):
                        try:
                            existing_enhanced_lag_policy = child["l3extVirtualLIfPLagPolAtt"]["children"][0]["l3extRsVSwitchEnhancedLagPol"]["attributes"][
                                "tDn"
                            ].split("enlacplagp-")[1]
                        except (AttributeError, IndexError, KeyError):
                            existing_enhanced_lag_policy = ""

                        if enhanced_lag_policy == "":
                            child_configs.append(
                                dict(
                                    l3extVirtualLIfPLagPolAtt=dict(
                                        attributes=dict(status="deleted"),
                                    ),
                                )
                            )

            if enhanced_lag_policy != "":
                child = [
                    dict(
                        l3extRsVSwitchEnhancedLagPol=dict(
                            attributes=dict(tDn="{0}/vswitchpolcont/enlacplagp-{1}".format(tDn, enhanced_lag_policy)),
                        )
                    ),
                ]
                if enhanced_lag_policy != existing_enhanced_lag_policy and existing_enhanced_lag_policy != "":
                    child.append(
                        dict(
                            l3extRsVSwitchEnhancedLagPol=dict(
                                attributes=dict(status="deleted", tDn="{0}/vswitchpolcont/enlacplagp-{1}".format(tDn, existing_enhanced_lag_policy)),
                            )
                        )
                    )
                child_configs.append(dict(l3extVirtualLIfPLagPolAtt=dict(attributes=dict(), children=child)))

        aci.payload(
            aci_class="l3extRsDynPathAtt",
            class_config=dict(
                floatingAddr=floating_ip,
                forgedTransmit=forged_transmit,
                macChange=mac_change,
                promMode=promiscuous_mode,
                encap=access_encap,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="l3extRsDynPathAtt")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
