#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Jacob McGill (@jmcgill298)
# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_epg_to_contract
short_description: Bind EPGs to Contracts (fv:RsCons, fv:RsProv, fv:RsProtBy, fv:RsConsIf, and fv:RsIntraEpg)
description:
- Bind EPGs to Contracts on Cisco ACI fabrics.
notes:
- The C(tenant), C(app_profile), C(EPG), and C(Contract) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_ap), M(cisco.aci.aci_epg), and M(cisco.aci.aci_contract) modules can be used for this.
options:
  ap:
    description:
    - Name of an existing application network profile, that will contain the EPGs.
    type: str
    aliases: [ app_profile, app_profile_name ]
  contract:
    description:
    - The name of the contract or contract interface.
    type: str
    aliases: [ contract_name, contract_interface ]
  contract_type:
    description:
    - Determines the type of the Contract.
    type: str
    required: true
    choices: [ consumer, provider, taboo, interface, intra_epg ]
  epg:
    description:
    - The name of the end point group.
    type: str
    aliases: [ epg_name ]
  priority:
    description:
    - QoS class.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ level1, level2, level3, level4, level5, level6, unspecified ]
  provider_match:
    description:
    - The matching algorithm for Provided Contracts.
    - The APIC defaults to C(at_least_one) when unset during creation.
    type: str
    choices: [ all, at_least_one, at_most_one, none ]
  contract_label:
    description:
    - Contract label to match
    type: str
  subject_label:
    description:
    - Subject label to match
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

seealso:
- module: cisco.aci.aci_ap
- module: cisco.aci.aci_epg
- module: cisco.aci.aci_contract
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(fv:RsCons), B(fv:RsProv), B(fv:RsProtBy), B(fv:RsConsIf), and B(fv:RsIntraEpg).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new contract to EPG binding
  cisco.aci.aci_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    contract: anstest_http
    contract_type: provider
    contract_label: contractlabel
    subject_label: subjlabel
    state: present
  delegate_to: localhost

- name: Remove an existing contract to EPG binding
  cisco.aci.aci_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    contract: anstest_http
    contract_type: provider
    state: absent
  delegate_to: localhost

- name: Query a specific contract to EPG binding
  cisco.aci.aci_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    contract: anstest_http
    contract_type: provider
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all provider contract to EPG bindings
  cisco.aci.aci_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import ACI_CLASS_MAPPING, CONTRACT_LABEL_MAPPING, PROVIDER_MATCH_MAPPING, SUBJ_LABEL_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        contract_type=dict(type="str", required=True, choices=["consumer", "provider", "taboo", "interface", "intra_epg"]),
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),  # Not required for querying all objects
        epg=dict(type="str", aliases=["epg_name"]),  # Not required for querying all objects
        contract=dict(type="str", aliases=["contract_name", "contract_interface"]),  # Not required for querying all objects
        priority=dict(type="str", choices=["level1", "level2", "level3", "level4", "level5", "level6", "unspecified"]),
        provider_match=dict(type="str", choices=["all", "at_least_one", "at_most_one", "none"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        contract_label=dict(type="str"),
        subject_label=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["ap", "contract", "epg", "tenant"]],
            ["state", "present", ["ap", "contract", "epg", "tenant"]],
        ],
    )

    ap = module.params.get("ap")
    contract = module.params.get("contract")
    contract_type = module.params.get("contract_type")
    epg = module.params.get("epg")
    priority = module.params.get("priority")
    provider_match = module.params.get("provider_match")
    if provider_match is not None:
        provider_match = PROVIDER_MATCH_MAPPING[provider_match]
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    contract_label = module.params.get("contract_label")
    subject_label = module.params.get("subject_label")

    aci_class = ACI_CLASS_MAPPING[contract_type]["class"]
    aci_rn = ACI_CLASS_MAPPING[contract_type]["rn"]
    aci_name = ACI_CLASS_MAPPING[contract_type]["name"]
    child_classes = []

    if contract_type != "provider" and provider_match is not None:
        module.fail_json(msg="the 'provider_match' is only configurable for Provided Contracts")

    if contract_type in ["taboo", "interface", "intra_epg"] and (contract_label is not None or subject_label is not None):
        module.fail_json(msg="the 'contract_label' and 'subject_label' are not configurable for {0} contracts".format(contract_type))

    if contract_type not in ["taboo", "interface", "intra_epg"]:
        contract_label_class = CONTRACT_LABEL_MAPPING.get(contract_type)
        subject_label_class = SUBJ_LABEL_MAPPING.get(contract_type)
        child_classes = [subject_label_class, contract_label_class]

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvAp",
            aci_rn="ap-{0}".format(ap),
            module_object=ap,
            target_filter={"name": ap},
        ),
        subclass_2=dict(
            aci_class="fvAEPg",
            aci_rn="epg-{0}".format(epg),
            module_object=epg,
            target_filter={"name": epg},
        ),
        subclass_3=dict(
            aci_class=aci_class,
            aci_rn="{0}{1}".format(aci_rn, contract),
            module_object=contract,
            target_filter={aci_name: contract},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if contract_label is not None:
            child_configs.append({contract_label_class: {"attributes": {"name": contract_label}}})
        if subject_label is not None:
            child_configs.append({subject_label_class: {"attributes": {"name": subject_label}}})
        aci.payload(
            aci_class=aci_class,
            class_config={"matchT": provider_match, "prio": priority, aci_name: contract},
            child_configs=child_configs,
        )

        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
