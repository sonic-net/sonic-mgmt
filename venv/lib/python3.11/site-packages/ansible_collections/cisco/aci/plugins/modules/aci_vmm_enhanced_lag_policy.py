#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Dev Sinha (@DevSinha13) <devsinh@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_vmm_enhanced_lag_policy
version_added: "2.12.0"
short_description: Manage Enhanced LACP Policy for Virtual Machine Manager (VMM) in Cisco ACI (lacp:EnhancedLagPol)
description:
- Manage Enhanced LACP Policy for VMM domains on Cisco ACI fabrics.
- The Enhanced LACP Policy allows you to configure advanced Link Aggregation Control Protocol settings for virtual switches in VMM domains.

options:
  name:
    description:
    - The name of the Enhanced LACP Policy.
    type: str
  domain:
    description:
    - The name of the virtual domain profile where the Enhanced LACP Policy is applied.
    type: str
    aliases: [ domain_name, domain_profile ]
  vm_provider:
    description:
    - The virtualization platform provider for the VMM domain.
    type: str
    choices: [ cloudfoundry, kubernetes, microsoft, openshift, openstack, redhat, vmware ]
  lacp_mode:
    description:
    - The LACP mode for the policy.
    - Determines whether the policy initiates or responds to LACP negotiations.
    - The APIC defaults to C(active) when unset during creation.
    type: str
    choices: [ active, passive ]
  load_balancing_mode:
    description:
    - The load balancing algorithm for distributing traffic across links in the port channel.
    - See the APIC Management Information Model reference for more details.
    - The APIC defaults to C(src-dst-ip) when unset during creation
    type: str
    choices:
    - dst-ip
    - dst-ip-l4port
    - dst-ip-vlan
    - dst-ip-l4port-vlan
    - dst-mac
    - dst-l4port
    - src-ip
    - src-ip-l4port
    - src-ip-vlan
    - src-ip-l4port-vlan
    - src-mac
    - src-l4port
    - src-dst-ip
    - src-dst-ip-l4port
    - src-dst-ip-vlan
    - src-dst-ip-l4port-vlan
    - src-dst-mac
    - src-dst-l4port
    - src-port-id
    - vlan
  number_uplinks:
    description:
    - The minimum number of uplinks required for the port channel.
    - Must be a value between 2 and 8.
    - The APIC defaults to 2 when unset during creation
    type: int
  state:
    description:
    - The desired state of the Enhanced LACP Policy.
    - Use C(present) to create or update the policy.
    - Use C(absent) to delete the policy.
    - Use C(query) to retrieve information about the policy.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- The I(vmm_domain) and I(vSwitch_policy) must exist before using this module in a playbook.
- The modules M(cisco.aci.aci_domain) and M(cisco.aci.aci_vmm_vswitch_policy) can be used for this.
seealso:
- module: cisco.aci.aci_domain
- module: cisco.aci.aci_vmm_vswitch_policy
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(lacp:EnhancedLagPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dev Sinha (@DevSinha13)
"""

EXAMPLES = r"""
- name: Create an Enhanced LACP Policy
  cisco.aci.aci_vmm_enhanced_lag_policy:
    host: apic.example.com
    username: admin
    password: SomeSecretPassword
    name: my_enhanced_lag_policy
    domain: my_vmm_domain
    vm_provider: vmware
    lacp_mode: active
    load_balancing_mode: src-dst-ip
    number_uplinks: 4
    state: present

- name: Update an existing Enhanced LACP Policy
  cisco.aci.aci_vmm_enhanced_lag_policy:
    host: apic.example.com
    username: admin
    password: SomeSecretPassword
    name: my_enhanced_lag_policy
    domain: my_vmm_domain
    vm_provider: vmware
    lacp_mode: passive
    load_balancing_mode: src-dst-ip-l4port
    number_uplinks: 6
    state: present

- name: Query a specific Enhanced LACP Policy
  cisco.aci.aci_vmm_enhanced_lag_policy:
    host: apic.example.com
    username: admin
    password: SomeSecretPassword
    name: my_enhanced_lag_policy
    domain: my_vmm_domain
    vm_provider: vmware
    state: query
  register: query_result

- name: Query all Enhanced LACP Policies in a VMM domain
  cisco.aci.aci_vmm_enhanced_lag_policy:
    host: apic.example.com
    username: admin
    password: SomeSecretPassword
    domain: my_vmm_domain
    vm_provider: vmware
    state: query
  register: query_all_result

- name: Delete an Enhanced LACP Policy
  cisco.aci.aci_vmm_enhanced_lag_policy:
    host: apic.example.com
    username: admin
    password: SomeSecretPassword
    name: my_enhanced_lag_policy
    domain: my_vmm_domain
    vm_provider: vmware
    state: absent
"""
RETURN = r"""
current:
  description: The existing configuration of the Enhanced LACP Policy from the APIC after the module has finished.
  returned: success
  type: list
  sample:
    [
        {
            "lacpEnhancedLagPol": {
                "attributes": {
                    "name": "test_enhanced_lag_policy",
                    "mode": "active",
                    "lbmode": "src-dst-ip",
                    "numLinks": "4",
                    "dn": "uni/vmmp-VMware/dom-test_vmm_dom/vswitchpolcont/enlacplagp-test_enhanced_lag_policy"
                }
            }
        }
    ]
error:
  description: The error information as returned from the APIC.
  returned: failure
  type: dict
  sample:
    {
        "code": "801",
        "text": "property name of enlacplagp-test_enhanced_lag_policy failed validation"
    }
proposed:
  description: The configuration sent to the APIC.
  returned: info
  type: dict
  sample:
    {
        "lacpEnhancedLagPol": {
            "attributes": {
                "name": "test_enhanced_lag_policy",
                "mode": "active",
                "lbmode": "src-dst-ip",
                "numLinks": "4"
            }
        }
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    enhanced_lag_spec,
    aci_annotation_spec,
    aci_owner_spec,
)
from ansible_collections.cisco.aci.plugins.module_utils.constants import (
    VM_PROVIDER_MAPPING,
)


def main():

    # Remove nutanix from VM_PROVIDER_MAPPING as it is not supported
    CLEAN_VM_PROVIDER_MAPPING = VM_PROVIDER_MAPPING.copy()
    CLEAN_VM_PROVIDER_MAPPING.pop("nutanix")

    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(enhanced_lag_spec(name_is_required=False))
    argument_spec.update(
        domain=dict(type="str", aliases=["domain_name", "domain_profile"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        vm_provider=dict(type="str", choices=list(CLEAN_VM_PROVIDER_MAPPING)),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "domain", "vm_provider"]],
            ["state", "present", ["name", "domain", "vm_provider"]],
        ],
    )

    name = module.params.get("name")
    lacp_mode = module.params.get("lacp_mode")
    load_balancing_mode = module.params.get("load_balancing_mode")
    number_uplinks = module.params.get("number_uplinks")
    domain = module.params.get("domain")
    state = module.params.get("state")
    vm_provider = module.params.get("vm_provider")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="vmmProvP",
            aci_rn="vmmp-{0}".format(CLEAN_VM_PROVIDER_MAPPING.get(vm_provider)),
            module_object=vm_provider,
            target_filter={"vendor": vm_provider},
        ),
        subclass_1=dict(
            aci_class="vmmDomP",
            aci_rn="dom-{0}".format(domain),
            module_object=domain,
            target_filter={"name": domain},
        ),
        subclass_2=dict(
            aci_class="vmmVSwitchPolicyCont",
            aci_rn="vswitchpolcont",
            module_object="vswitchpolcont",
        ),
        subclass_3=dict(
            aci_class="lacpEnhancedLagPol",
            aci_rn="enlacplagp-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="lacpEnhancedLagPol",
            class_config=dict(
                name=name,
                mode=lacp_mode,
                lbmode=load_balancing_mode,
                numLinks=number_uplinks,
            ),
        )

        aci.get_diff(aci_class="lacpEnhancedLagPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
