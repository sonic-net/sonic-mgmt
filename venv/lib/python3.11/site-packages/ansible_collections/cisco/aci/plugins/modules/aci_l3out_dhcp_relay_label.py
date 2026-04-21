#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_dhcp_relay_label
short_description: Manage Layer 3 Outside (L3Out) DHCP Relay Label (dhcp:Lbl)
description:
- Manage DHCP Relay Labels for L3Out Logical Interface Profiles on Cisco ACI fabrics.
- A DHCP Relay Label contains the name of an existing DHCP Relay Policy for the label,
  the scope, and a DHCP Option Policy.
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
    - The name of an existing node profile.
    type: str
    aliases: [ node_profile_name, logical_node ]
  interface_profile:
    description:
    - The name of an existing interface profile.
    type: str
    aliases: [ interface_profile_name, logical_interface ]
  dhcp_relay_label:
    description:
    - The name/label of an existing DHCP Relay Policy.
    type: str
    aliases: [ name, relay_policy ]
  scope:
    description:
    - The scope is the owner of the relay server.
    - The APIC defaults to C(infra) when unset during creation.
    type: str
    choices: [ infra, tenant ]
    aliases: [ owner ]
  dhcp_option_policy:
    description:
    - The name of an existing DHCP Option Policy to be associated with the DCHP Relay Policy.
    - The DHCP option policy supplies DHCP clients with configuration parameters
      such as domain, nameserver, and subnet router addresses.
    - Passing an empty string will delete the current linked DHCP Option Policy.
      However, this will associate the DHCP Relay Label to the default DHCP Option Policy
      from the common Tenant.
    type: str
    aliases: [ dhcp_option_policy_name ]
  description:
    description:
    - The description of the DHCP Relay Label.
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
- The C(tenant), C(l3out), C(node_profile), C(interface_profile) and C(relay_policy) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l3out), M(cisco.aci.aci_l3out_logical_node_profile), M(cisco.aci.aci_l3out_logical_interface_profile)
  and M(cisco.aci.aci_dhcp_relay) can be used for this.
- If C(dhcp_option_policy) is used, it must exist before using this module in your playbook.
  The M(cisco.aci.aci_dhcp_option_policy) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_l3out_logical_node_profile
- module: cisco.aci.aci_l3out_logical_interface_profile
- module: cisco.aci.aci_dhcp_relay
- module: cisco.aci.aci_dhcp_option_policy
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a new L3Out DHCP Relay Label
  cisco.aci.aci_l3out_eigrp_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    dhcp_relay_label: my_dhcp_relay_label
    scope: tenant
    dhcp_option_policy: my_dhcp_option_policy
    state: present
  delegate_to: localhost

- name: Delete an L3Out DHCP Relay Label
  cisco.aci.aci_l3out_eigrp_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    dhcp_relay_label: my_dhcp_relay_label
    state: absent
  delegate_to: localhost

- name: Query an L3Out DHCP Relay Label
  cisco.aci.aci_l3out_eigrp_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    dhcp_relay_label: my_dhcp_relay_label
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        node_profile=dict(type="str", aliases=["node_profile_name", "logical_node"]),
        interface_profile=dict(type="str", aliases=["interface_profile_name", "logical_interface"]),
        dhcp_relay_label=dict(type="str", aliases=["name", "relay_policy"]),
        scope=dict(type="str", choices=["infra", "tenant"], aliases=["owner"]),
        dhcp_option_policy=dict(type="str", aliases=["dhcp_option_policy_name"]),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "l3out", "node_profile", "interface_profile", "dhcp_relay_label"]],
            ["state", "present", ["tenant", "l3out", "node_profile", "interface_profile", "dhcp_relay_label"]],
        ],
    )

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
    dhcp_relay_label = module.params.get("dhcp_relay_label")
    scope = module.params.get("scope")
    dhcp_option_policy = module.params.get("dhcp_option_policy")
    description = module.params.get("description")
    state = module.params.get("state")

    aci = ACIModule(module)

    child_classes = ["dhcpRsDhcpOptionPol"]

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
            aci_rn="lifp-[{0}]".format(interface_profile),
            module_object=interface_profile,
            target_filter={"name": interface_profile},
        ),
        subclass_4=dict(
            aci_class="dhcpLbl",
            aci_rn="dhcplbl-[{0}]".format(dhcp_relay_label),
            module_object=dhcp_relay_label,
            target_filter={"name": dhcp_relay_label},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = [dict(dhcpRsDhcpOptionPol=dict(attributes=dict(tnDhcpOptionPolName=dhcp_option_policy)))]

        aci.payload(
            aci_class="dhcpLbl",
            class_config=dict(
                descr=description,
                name=dhcp_relay_label,
                owner=scope,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="dhcpLbl")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
