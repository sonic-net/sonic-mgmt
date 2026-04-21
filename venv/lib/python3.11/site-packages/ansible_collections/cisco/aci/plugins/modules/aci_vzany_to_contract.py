#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_vzany_to_contract
short_description: Attach contracts to vzAny (vz:RsAnyToProv, vz:RsAnyToCons, and vz:RsAnyToConsIf)
description:
- Bind contracts to vzAny on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of the Tenant.
    type: str
    aliases: [ tenant_name ]
  vrf:
    description:
    - The name of the VRF.
    type: str
    aliases: [ context, vrf_name ]
  contract:
    description:
    - The name of the contract or contract interface.
    type: str
    aliases: [ contract_name ]
  type:
    description:
    - Determines if this is a provided or consumed contract or a consumed contract interface.
    type: str
    aliases: [ contract_type ]
    required: true
    choices: [ provider, consumer, interface ]
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
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_vrf
- module: cisco.aci.aci_contract
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(vz:RsAnyToProv), B(vz:RsAnyToCons), and B(vz:RsAnyToConsIf).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Marcel Zehnder (@maercu)
"""

EXAMPLES = r"""
- name: Add a new contract to vzAny
  cisco.aci.aci_vzany_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: vzatest
    vrf: vzatest
    contract: vzatest_http
    type: provider
    state: present
  delegate_to: localhost

- name: Remove an existing contract from vzAny
  cisco.aci.aci_vzany_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: vzatest
    vrf: vzatest
    contract: vzatest_http
    type: provider
    state: absent
  delegate_to: localhost

- name: Query a specific contract to vzAny binding
  cisco.aci.aci_vzany_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: vzatest
    vrf: vzatest
    contract: vzatest_http
    type: provider
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all provider contract to vzAny bindings
  cisco.aci.aci_vzany_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    type: provider
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


ACI_CLASS_MAPPING = dict(
    provider={"class": "vzRsAnyToProv", "rn": "rsanyToProv-", "target_attribute": "tnVzBrCPName"},
    consumer={"class": "vzRsAnyToCons", "rn": "rsanyToCons-", "target_attribute": "tnVzBrCPName"},
    interface={"class": "vzRsAnyToConsIf", "rn": "rsanyToConsIf-", "target_attribute": "tnVzCPIfName"},
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        vrf=dict(type="str", aliases=["context", "vrf_name"]),
        contract=dict(type="str", aliases=["contract_name"]),
        type=dict(type="str", required=True, choices=["provider", "consumer", "interface"], aliases=["contract_type"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[["state", "absent", ["contract", "vrf", "tenant"]], ["state", "present", ["contract", "vrf", "tenant"]]],
    )

    tenant = module.params.get("tenant")
    vrf = module.params.get("vrf")
    contract = module.params.get("contract")
    type = module.params.get("type")
    state = module.params.get("state")

    aci_class = ACI_CLASS_MAPPING[type]["class"]
    aci_rn = ACI_CLASS_MAPPING[type]["rn"]
    aci_target_attribute = ACI_CLASS_MAPPING[type]["target_attribute"]

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(aci_class="fvTenant", aci_rn="tn-{0}".format(tenant), module_object=tenant, target_filter={"name": tenant}),
        subclass_1=dict(aci_class="fvCtx", aci_rn="ctx-{0}".format(vrf), module_object=vrf, target_filter={"name": vrf}),
        subclass_2=dict(aci_class="vzAny", aci_rn="any", module_object="any", target_filter={"name": "any"}),
        subclass_3=dict(aci_class=aci_class, aci_rn="{0}{1}".format(aci_rn, contract), module_object=contract, target_filter={aci_target_attribute: contract}),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(aci_class=aci_class, class_config={aci_target_attribute: contract})

        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
