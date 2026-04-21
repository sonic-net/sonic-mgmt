#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_esg_to_contract
short_description: Bind ESGs to Contracts (fv:RsCons, fv:RsProv, fv:RsConsIf, and fv:RsIntraEpg)
description:
- Bind ESGs to Contracts on Cisco ACI fabrics.
notes:
- The C(tenant), C(ap), C(esg), and C(contract) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_ap), M(cisco.aci.aci_esg), and M(cisco.aci.aci_contract) modules can be used for this.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  ap:
    description:
    - Name of an existing application network profile, that will contain the ESGs.
    type: str
    aliases: [ app_profile, app_profile_name ]
  esg:
    description:
    - The name of the end point security group.
    type: str
    aliases: [ esg_name ]
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
    choices: [ consumer, provider, interface, intra_esg ]
  priority:
    description:
    - QoS class.
    - The APIC defaults to C(unspecified) when unset during creation.
    - This argument is not supported for o(contract_type=intra_esg) contracts.
    type: str
    choices: [ level1, level2, level3, level4, level5, level6, unspecified ]
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
- module: cisco.aci.aci_ap
- module: cisco.aci.aci_esg
- module: cisco.aci.aci_contract
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(fv:RsCons), B(fv:RsProv), B(fv:RsConsIf), and B(fv:RsIntraEpg).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new contract to ESG binding
  cisco.aci.aci_esg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    esg: anstest
    contract: anstest_http
    contract_type: provider
    state: present
  delegate_to: localhost

- name: Query a specific contract to ESG binding
  cisco.aci.aci_esg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    esg: anstest
    contract: anstest_http
    contract_type: provider
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all provider contract to ESG bindings
  cisco.aci.aci_esg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    contract_type: provider
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove an existing contract to ESG binding
  cisco.aci.aci_esg_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    esg: anstest
    contract: anstest_http
    contract_type: provider
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import ACI_CLASS_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        contract_type=dict(type="str", required=True, choices=["consumer", "provider", "interface", "intra_esg"]),
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),  # Not required for querying all objects
        esg=dict(type="str", aliases=["esg_name"]),  # Not required for querying all objects
        contract=dict(type="str", aliases=["contract_name", "contract_interface"]),  # Not required for querying all objects
        priority=dict(type="str", choices=["level1", "level2", "level3", "level4", "level5", "level6", "unspecified"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "ap", "esg", "contract"]],
            ["state", "present", ["tenant", "ap", "esg", "contract"]],
        ],
    )

    contract_type = module.params.get("contract_type")
    tenant = module.params.get("tenant")
    ap = module.params.get("ap")
    esg = module.params.get("esg")
    contract = module.params.get("contract")
    priority = module.params.get("priority")
    state = module.params.get("state")

    if contract_type == "intra_esg" and priority is not None:
        module.fail_json(msg="The 'priority' argument is not supported for the 'intra_esg' contract type.")

    aci_class = ACI_CLASS_MAPPING[contract_type]["class"]
    aci_rn = ACI_CLASS_MAPPING[contract_type]["rn"]
    aci_name = ACI_CLASS_MAPPING[contract_type]["name"]

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
            aci_rn="esg-{0}".format(esg),
            module_object=esg,
            target_filter={"name": esg},
        ),
        subclass_3=dict(
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
            class_config={"prio": priority, aci_name: contract},
        )

        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
