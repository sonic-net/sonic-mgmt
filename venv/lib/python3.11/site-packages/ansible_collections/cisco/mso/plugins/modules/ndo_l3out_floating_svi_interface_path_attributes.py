#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_floating_svi_interface_path_attributes
version_added: "2.12.0"
short_description: Manage L3Out Floating SVI Interface Path Attributes on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Out Floating SVI Interface Path Attributes on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Akini Ross (@akinross)
options:
  template:
    description:
    - The name of the template.
    - The template must be an L3Out template.
    - This parameter or O(template_id) is required.
    type: str
    aliases: [ l3out_template ]
  template_id:
    description:
    - The ID of the L3Out template.
    - This parameter or O(template) is required.
    type: str
    aliases: [ l3out_template_id ]
  l3out:
    description:
    - The name of the L3Out.
    - This parameter or O(l3out_uuid) is required.
    type: str
    aliases: [ l3out_name ]
  l3out_uuid:
    description:
    - The UUID of the L3Out.
    - This parameter or O(l3out) is required.
    type: str
  node_id:
    description:
    - The Anchor Node ID of the L3Out Floating SVI Interface.
    type: str
    required: true
    aliases: [ node, anchor_node_id ]
  encapsulation_type:
    description:
    - The encapsulation type of the interface.
    type: str
    default: vlan
    aliases: [ encap_type ]
    choices: [ vlan, vxlan ]
  encapsulation_value:
    description:
    - The encapsulation value of the interface.
    - The option O(encapsulation_type=vlan), specifies VLAN ID which must be in the range 1 - 4094.
    - The option O(encapsulation_type=vxlan), specifies VXLAN Network Identifier (VNI) which must be in the range 5000 - 16777215.
    type: int
    required: true
    aliases: [ encap, encapsulation, encapsulation_id ]
  domain_type:
    description:
    - The type of the domain.
    type: str
    choices: [ vmm, physical ]
  domain_provider:
    description:
    - The provider of the domain.
    type: str
    choices: [ cloudfoundry, kubernetes, microsoft, openshift, openstack, redhat, vmware, nutanix ]
  domain:
    description:
    - The name of the domain.
    type: str
    aliases: [ domain_name ]
  forged_transmit:
    description:
    - Indicates whether forged transmit is enabled.
    type: bool
  mac_address_change:
    description:
    - Indicates whether MAC address change is enabled.
    type: bool
  promiscuous_mode:
    description:
    - Indicates whether promiscuous mode is enabled.
    type: bool
  enhanced_lag_policy:
    description:
    - The name of the enhanced LAG policy.
    - The enhanced LAG policy must be configured on APIC in the provided VMM domain before using this attribute in your playbook.
    type: str
    aliases: [ enhanced_lag_policy_name ]
  primary_ipv4_address:
    description:
    - The primary IPv4 address.
    type: str
    aliases: [ primary_ipv4 ]
  primary_ipv6_address:
    description:
    - The primary IPv6 address.
    type: str
    aliases: [ primary_ipv6 ]
  state:
    description:
    - Determines the desired state of the resource.
    - Use C(absent) to remove the resource.
    - Use C(query) to list the resource.
    - Use C(present) to create or update the resource.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) or O(template_id) must exist before using this module in your playbook.
  The M(cisco.mso.ndo_template) module can be used for this.
- The O(l3out) or O(l3out_uuid) must exist before using this module in your playbook.
  The M(cisco.mso.ndo_l3out_template) module can be used for this.
- The L3Out Floating SVI Interface identified by O(node_id), O(encapsulation_type), and O(encapsulation_value)
  must exist before using this module in your playbook.
  The M(cisco.mso.ndo_l3out_floating_svi_interface) module can be used for this.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_l3out_template
- module: cisco.mso.ndo_l3out_floating_svi_interface
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create Path Attributes for a L3Out Floating SVI Interface
  cisco.mso.ndo_l3out_floating_svi_interface_path_attributes:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    node_id: 101
    encapsulation_type: vlan
    encapsulation_value: 1200
    domain_type: vmm
    domain_provider: vmware
    domain: domain_name
    forged_transmit: true
    mac_address_change: true
    promiscuous_mode: true
    enhanced_lag_policy: enhanced_lag_policy_name
    primary_ipv4_address: 192.0.2.1
    primary_ipv6_address: 2001:db8::1
    state: present

- name: Update the Path Attributes of a L3Out Floating SVI Interface
  cisco.mso.ndo_l3out_floating_svi_interface_path_attributes:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: "{{ l3out_template.current.templateId }}"
    l3out_uuid: "{{ l3out.current.uuid }}"
    node_id: 101
    encapsulation_type: vlan
    encapsulation_value: 1200
    domain_type: vmm
    domain_provider: vmware
    domain: domain_name
    forged_transmit: false
    mac_address_change: false
    promiscuous_mode: false
    enhanced_lag_policy: enhanced_lag_policy_name
    primary_ipv4_address: 192.0.2.2
    primary_ipv6_address: 2001:db8::2
    state: present

- name: Query the Path Attributes of an existing L3Out Floating SVI Interface
  cisco.mso.ndo_l3out_floating_svi_interface_path_attributes:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    node_id: 101
    encapsulation_type: vlan
    encapsulation_value: 1200
    domain_type: vmm
    domain_provider: vmware
    domain: domain_name
    state: query
  register: query_one

- name: Query all existing Path Attributes of L3Out Floating SVI Interface
  cisco.mso.ndo_l3out_floating_svi_interface_path_attributes:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    node_id: 101
    encapsulation_type: vlan
    encapsulation_value: 1200
    state: query
  register: query_all

- name: Delete the Path Attributes of an existing L3Out Floating SVI Interface
  cisco.mso.ndo_l3out_floating_svi_interface_path_attributes:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: l3out_template
    l3out: l3out_name
    node_id: 101
    encapsulation_type: vlan
    encapsulation_value: 1200
    domain_type: vmm
    domain_provider: vmware
    domain: domain_name
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.constants import (
    DOMAIN_TYPE_MAP,
    VM_DOMAIN_PROVIDER_MAP,
    BOOL_TO_ENABLED_OR_DISABLED_STRING_MAP,
)
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", aliases=["l3out_template"]),
        template_id=dict(type="str", aliases=["l3out_template_id"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        l3out_uuid=dict(type="str"),
        node_id=dict(type="str", aliases=["node", "anchor_node_id"], required=True),
        encapsulation_type=dict(type="str", choices=["vlan", "vxlan"], aliases=["encap_type"], default="vlan"),
        encapsulation_value=dict(type="int", aliases=["encap", "encapsulation", "encapsulation_id"], required=True),
        domain_type=dict(type="str", choices=list(DOMAIN_TYPE_MAP)),
        domain_provider=dict(type="str", choices=list(VM_DOMAIN_PROVIDER_MAP)),
        domain=dict(type="str", aliases=["domain_name"]),
        forged_transmit=dict(type="bool"),
        mac_address_change=dict(type="bool"),
        promiscuous_mode=dict(type="bool"),
        enhanced_lag_policy=dict(type="str", aliases=["enhanced_lag_policy_name"]),
        primary_ipv4_address=dict(type="str", aliases=["primary_ipv4"]),
        primary_ipv6_address=dict(type="str", aliases=["primary_ipv6"]),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["domain_type", "domain"]],
            ["state", "absent", ["domain_type", "domain"]],
            ["domain_type", "vmm", ["domain_provider"]],
        ],
        required_one_of=[
            ["template", "template_id"],
            ["l3out", "l3out_uuid"],
        ],
        mutually_exclusive=[
            ["template", "template_id"],
            ["l3out", "l3out_uuid"],
        ],
    )

    mso = MSOModule(module)
    mso_templates = MSOTemplates(mso)

    template_name = mso.params.get("template")
    template_id = mso.params.get("template_id")
    l3out = mso.params.get("l3out")
    l3out_uuid = mso.params.get("l3out_uuid")
    node_id = mso.params.get("node_id")
    encap = {"encapType": mso.params.get("encapsulation_type"), "value": mso.params.get("encapsulation_value")}
    domain_type = DOMAIN_TYPE_MAP.get(mso.params.get("domain_type"))
    domain = None
    if domain_type == "physicalDomain":
        domain = "uni/phys-{0}".format(mso.params.get("domain"))
    elif domain_type == "vmmDomain":
        domain = "uni/vmmp-{0}/dom-{1}".format(VM_DOMAIN_PROVIDER_MAP.get(mso.params.get("domain_provider")), mso.params.get("domain"))
    forged_transmit = BOOL_TO_ENABLED_OR_DISABLED_STRING_MAP.get(mso.params.get("forged_transmit"))
    mac_address_change = BOOL_TO_ENABLED_OR_DISABLED_STRING_MAP.get(mso.params.get("mac_address_change"))
    promiscuous_mode = BOOL_TO_ENABLED_OR_DISABLED_STRING_MAP.get(mso.params.get("promiscuous_mode"))
    enhanced_lag_policy = mso.params.get("enhanced_lag_policy")
    primary_ipv4_address = mso.params.get("primary_ipv4_address")
    primary_ipv6_address = mso.params.get("primary_ipv6_address")
    state = mso.params.get("state")

    mso_template = mso_templates.get_template("l3out", template_name, template_id)
    mso_template.validate_template("l3out")
    l3out_object = mso_template.get_l3out_object(l3out_uuid, l3out, True)
    pod_id = mso.get_site_interface_details(site_id=mso_template.template.get("l3outTemplate", {}).get("siteId"), node=node_id)
    floating_svi_object = mso_template.get_l3out_floating_svi_interface(l3out_object.details, pod_id, node_id, encap, True)

    match = mso_template.get_l3out_floating_svi_interface_path_attributes(floating_svi_object.details, domain_type, domain)
    if match and domain_type and domain:
        set_floating_svi_interface_path_attributes_details(mso_template, match.details, l3out_object, floating_svi_object)
        mso.existing = mso.previous = copy.deepcopy(match.details)  # Query a specific object
    elif match:
        mso.existing = [set_floating_svi_interface_path_attributes_details(mso_template, obj, l3out_object, floating_svi_object) for obj in match]

    path_attributes_path = "/l3outTemplate/l3outs/{0}/floatingSviInterfaces/{1}/svi/floatingPathAttributes/{2}".format(
        l3out_object.index, floating_svi_object.index, match.index if match else "-"
    )

    ops = []

    if state == "present":
        mso_values = {
            "domain": domain,
            "domainType": domain_type,
            "forgedTransmit": forged_transmit,
            "macAddrChange": mac_address_change,
            "promiscuousMode": promiscuous_mode,
            "enhancedLagPolicy": enhanced_lag_policy,
            "primaryAddressV4": primary_ipv4_address,
            "primaryAddressV6": primary_ipv6_address,
        }

        if match:
            append_update_ops_data(ops, match.details, path_attributes_path, mso_values)
            mso.sanitize(match.details, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=path_attributes_path, value=mso.sent))

        # update mso.proposed with details that are not included in the payload
        set_floating_svi_interface_path_attributes_details(mso_template, mso.proposed, l3out_object, floating_svi_object)

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=path_attributes_path))

    if not mso.module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        l3out_object = mso_template.get_l3out_object(l3out_uuid, l3out, True, search_object=response)
        floating_svi_object = mso_template.get_l3out_floating_svi_interface(l3out_object.details, pod_id, node_id, encap, True)
        match = mso_template.get_l3out_floating_svi_interface_path_attributes(floating_svi_object.details, domain_type, domain)
        if match:
            set_floating_svi_interface_path_attributes_details(mso_template, match.details, l3out_object, floating_svi_object)
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif mso.module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}
    mso.exit_json()


def set_floating_svi_interface_path_attributes_details(mso_template, floating_svi_interface_path_attributes, l3out_object, floating_svi_object):
    floating_svi_interface_path_attributes["templateName"] = mso_template.template_name
    floating_svi_interface_path_attributes["templateId"] = mso_template.template_id
    floating_svi_interface_path_attributes["l3outName"] = l3out_object.details.get("name")
    floating_svi_interface_path_attributes["l3outUUID"] = l3out_object.details.get("uuid")
    floating_svi_interface_path_attributes["podID"] = floating_svi_object.details.get("podID")
    floating_svi_interface_path_attributes["nodeID"] = floating_svi_object.details.get("nodeID")
    floating_svi_interface_path_attributes["encap"] = floating_svi_object.details.get("encap")
    return floating_svi_interface_path_attributes


if __name__ == "__main__":
    main()
