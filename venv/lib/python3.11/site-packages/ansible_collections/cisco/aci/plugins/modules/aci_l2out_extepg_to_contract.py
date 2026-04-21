#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Sudhakar Shet Kudtarkar (@kudtarkar1)
# Copyright: (c) 2020, Shreyas Srish <ssrish@cisco.com>
# Copyright: (c) 2021, Oleksandr Kreshchenko (@alexkross)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l2out_extepg_to_contract
short_description: Bind Contracts to L2 External End Point Groups (EPGs) (fv:RsCons and fv:RsProv)
description:
- Bind Contracts to L2 External End Point Groups (EPGs) on ACI fabrics.
options:
  tenant:
    description:
    - Name of existing tenant.
    type: str
  l2out:
    description:
    - Name of the l2out.
    type: str
    aliases: ['l2out_name']
  extepg:
    description:
    - Name of the external end point group.
    type: str
    aliases: ['extepg_name', 'external_epg']
  contract:
    description:
    - Name of the contract.
    type: str
  contract_type:
    description:
    - The type of contract.
    type: str
    required: true
    choices: ['consumer', 'provider']
  priority:
    description:
    - This has four levels of priority.
    type: str
    choices: ['level1', 'level2', 'level3', 'unspecified']
  provider_match:
    description:
    - This is configurable for provided contracts.
    type: str
    choices: ['all', 'at_least_one', 'at_most_one', 'none']
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
- The C(tenant), C(l2out) and C(extepg) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l2out) and M(cisco.aci.aci_l2out_extepg) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B((fv:RsCons) B(fv:RsProv).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sudhakar Shet Kudtarkar (@kudtarkar1)
- Shreyas Srish (@shrsr)
- Oleksandr Kreshchenko (@alexkross)
"""

EXAMPLES = r"""
- name: Bind a contract to an L2 external EPG
  cisco.aci.aci_l2out_extepg_to_contract:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l2out: l2out
    extepg: testEpg
    contract: contract1
    contract_type: provider
    state: present
  delegate_to: localhost

- name: Remove existing contract from an L2 external EPG
  cisco.aco.aci_l2out_extepg_to_contract:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l2out: l2out
    extepg: testEpg
    contract: contract1
    contract_type: provider
    state: absent
  delegate_to: localhost

- name: Query a contract bound to an L2 external EPG
  cisco.aci.aci_l2out_extepg_to_contract:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    l2out: ansible_l2out
    extepg: ansible_extEpg
    contract: ansible_contract
    contract_type: provider
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all contracts relationships
  cisco.aci.aci_l2out_extepg_to_contract:
    host: apic
    username: admin
    password: SomeSecretePassword
    contract_type: provider
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
     sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class "/></imdata>'
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
    consumer={
        "class": "fvRsCons",
        "rn": "rscons-",
    },
    provider={
        "class": "fvRsProv",
        "rn": "rsprov-",
    },
)

PROVIDER_MATCH_MAPPING = dict(
    all="All",
    at_least_one="AtleastOne",
    at_most_one="tmostOne",
    none="None",
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        contract_type=dict(type="str", required=True, choices=["consumer", "provider"]),
        l2out=dict(type="str", aliases=["l2out_name"]),
        contract=dict(type="str"),
        priority=dict(type="str", choices=["level1", "level2", "level3", "unspecified"]),
        provider_match=dict(type="str", choices=["all", "at_least_one", "at_most_one", "none"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str"),
        extepg=dict(type="str", aliases=["extepg_name", "external_epg"]),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["extepg", "contract", "l2out", "tenant"]],
            ["state", "present", ["extepg", "contract", "l2out", "tenant"]],
        ],
    )

    l2out = module.params.get("l2out")
    contract = module.params.get("contract")
    contract_type = module.params.get("contract_type")
    extepg = module.params.get("extepg")
    priority = module.params.get("priority")
    provider_match = module.params.get("provider_match")
    if provider_match is not None:
        provider_match = PROVIDER_MATCH_MAPPING.get(provider_match)
    state = module.params.get("state")
    tenant = module.params.get("tenant")

    aci_class = ACI_CLASS_MAPPING.get(contract_type)["class"]
    aci_rn = ACI_CLASS_MAPPING.get(contract_type)["rn"]

    if contract_type == "consumer" and provider_match is not None:
        module.fail_json(msg="the 'provider_match' is only configurable for Provided Contracts")

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
            aci_class="l2extInstP",
            aci_rn="instP-{0}".format(extepg),
            module_object=extepg,
            target_filter={"name": extepg},
        ),
        subclass_3=dict(
            aci_class=aci_class,
            aci_rn="{0}{1}".format(aci_rn, contract),
            module_object=contract,
            target_filter={"tnVzBrCPName": contract},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=aci_class,
            class_config=dict(
                matchT=provider_match,
                prio=priority,
                tnVzBrCPName=contract,
            ),
        )

        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
