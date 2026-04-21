#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Faiz Mohammad (@Ziaf007) <faizmoh@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_node_mgmt_epg_to_contract
version_added: "2.12.0"
short_description: Bind Node Management EPGs to Contracts (fv:RsCons, fv:RsProv, fv:RsProtBy, fv:RsConsIf and mgmt:RsOoBProv)
description:
- Bind Node Management EPGs to Contracts on Cisco ACI fabrics.
notes:
- The O(epg) and O(contract) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_node_mgmt_epg), M(cisco.aci.aci_oob_contract) and M(cisco.aci.aci_contract) modules can be used for this.
options:
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
    choices: [ consumer, provider, taboo, interface ]
  epg:
    description:
    - The name of the Node Management end point group.
    type: str
    aliases: [ epg_name ]
  epg_type:
    description:
    - The type of the Node Management end point group.
    type: str
    required: true
    aliases: [ type ]
    choices: [ in_band, out_of_band ]
  priority:
    description:
    - Quality of Service (QoS) class.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ level1, level2, level3, level4, level5, level6, unspecified ]
  provider_match:
    description:
    - The matching algorithm for Provided Contracts.
    - The APIC defaults to C(at_least_one) when unset during creation.
    type: str
    choices: [ all, at_least_one, at_most_one, none ]
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
- module: cisco.aci.aci_node_mgmt_epg
- module: cisco.aci.aci_contract
- module: cisco.aci.aci_oob_contract
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(fv:RsCons), B(fv:RsProv), B(fv:RsProtBy), B(fv:RsConsIf), and B(mgmt:RsOoBProv).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Faiz Mohammad (@Ziaf007)
"""

EXAMPLES = r"""
- name: Add a new contract to Inband EPG binding
  cisco.aci.aci_node_mgmt_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    epg: anstest
    epg_type: in_band
    contract: anstest_http
    contract_type: provider
    priority: level2
    provider_match: at_least_one
    state: present
  delegate_to: localhost

- name: Add a new contract to Out-of-Band EPG binding
  cisco.aci.aci_node_mgmt_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    epg: anstest
    epg_type: out_of_band
    contract: anstest_http
    contract_type: provider
    priority: level3
    state: present
  delegate_to: localhost

- name: Update a contract of Inband EPG binding
  cisco.aci.aci_node_mgmt_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    epg: anstest
    epg_type: in_band
    contract: anstest_http
    contract_type: provider
    priority: level5
    provider_match: all
    state: present
  delegate_to: localhost

- name: Query a specific contract to EPG binding
  cisco.aci.aci_node_mgmt_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    epg: anstest
    epg_type: in_band
    contract: anstest_http
    contract_type: consumer
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all provider contract to EPG bindings
  cisco.aci.aci_node_mgmt_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    contract_type: provider
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove an existing contract to Inband EPG binding
  cisco.aci.aci_node_mgmt_epg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    epg: anstest
    epg_type: in_band
    contract: anstest_http
    contract_type: consumer
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible_collections.cisco.aci.plugins.module_utils.constants import ACI_CLASS_MAPPING, MANAGEMENT_EPG_CLASS_MAPPING, PROVIDER_MATCH_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        contract_type=dict(type="str", choices=["consumer", "provider", "taboo", "interface"], required=True),
        epg_type=dict(
            type="str", aliases=["type"], choices=["in_band", "out_of_band"], required=True
        ),  # required for querying as provider class for INB and OOB are different
        epg=dict(type="str", aliases=["epg_name"]),  # Not required for querying all objects
        contract=dict(type="str", aliases=["contract_name", "contract_interface"]),  # Not required for querying all objects
        priority=dict(type="str", choices=["level1", "level2", "level3", "level4", "level5", "level6", "unspecified"]),
        provider_match=dict(type="str", choices=["all", "at_least_one", "at_most_one", "none"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["epg", "contract"]],
            ["state", "present", ["epg", "contract"]],
        ],
    )

    epg_type = module.params.get("epg_type")
    contract = module.params.get("contract")
    contract_type = module.params.get("contract_type")
    epg = module.params.get("epg")
    priority = module.params.get("priority")
    provider_match = module.params.get("provider_match")
    if provider_match is not None:
        provider_match = PROVIDER_MATCH_MAPPING[provider_match]
    state = module.params.get("state")

    identifier = None
    if epg_type == "in_band":

        if contract_type != "provider" and provider_match is not None:
            module.fail_json(msg="the provider_match is only configurable for Provider Contracts")

        identifier = contract_type
        class_config = {"matchT": provider_match, "prio": priority, ACI_CLASS_MAPPING[contract_type]["name"]: contract}

    elif epg_type == "out_of_band":

        if contract_type != "provider":
            module.fail_json(msg="only provider contract_type is supported for out_of_band epg_type.")

        if provider_match is not None:
            module.fail_json(msg="The provider_match argument is not supported for out_of_band Provider contracts")

        identifier = "oob_provider"
        class_config = {"prio": priority, "tnVzOOBBrCPName": contract}

    aci_class = ACI_CLASS_MAPPING[identifier]["class"]
    aci_rn = ACI_CLASS_MAPPING[identifier]["rn"]
    aci_name = ACI_CLASS_MAPPING[identifier]["name"]

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="mgmtp",
            aci_rn="tn-mgmt/mgmtp-default",
            module_object=None,
        ),
        subclass_1=dict(
            aci_class=MANAGEMENT_EPG_CLASS_MAPPING[epg_type]["epg_class"],
            aci_rn="{0}{1}".format(MANAGEMENT_EPG_CLASS_MAPPING[epg_type]["epg_rn"], epg),
            module_object=epg,
            target_filter={"name": epg},
        ),
        subclass_2=dict(
            aci_class=aci_class,
            aci_rn="{0}{1}".format(aci_rn, contract),
            module_object=contract,
            target_filter={aci_name: contract},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=aci_class,
            class_config=class_config,
        )

        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
