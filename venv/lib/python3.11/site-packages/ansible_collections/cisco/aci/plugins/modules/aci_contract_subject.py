#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_contract_subject
short_description: Manage initial Contract Subjects (vz:Subj)
description:
- Manage initial Contract Subjects on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of the tenant.
    type: str
    aliases: [ tenant_name ]
  subject:
    description:
    - The contract subject name.
    type: str
    aliases: [ contract_subject, name, subject_name ]
  apply_both_direction:
    description:
    - The direction of traffic matching for the filter.
    type: str
    default: both
    choices: [ both, one-way ]
  contract:
    description:
    - The name of the Contract.
    type: str
    aliases: [ contract_name ]
  contract_type:
    description:
    - The type of contract, either standard or Out of Band (oob).
    type: str
    choices: [ standard, oob ]
    default: standard
  reverse_filter:
    description:
    - Determines if the APIC should reverse the src and dst ports to allow the
      return traffic back, since ACI is stateless filter.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  priority:
    description:
    - The QoS class.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ level1, level2, level3, unspecified ]
  dscp:
    description:
    - The target DSCP.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43,
               CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
    aliases: [ target ]
  priority_consumer_to_provider:
    description:
    - The QoS class of Filter Chain For Consumer to Provider.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ level1, level2, level3, unspecified ]
  dscp_consumer_to_provider:
    description:
    - The target DSCP of Filter Chain For Consumer to Provider.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43,
               CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
    aliases: [ target_consumer_to_provider ]
  priority_provider_to_consumer:
    description:
    - The QoS class of Filter Chain For Provider to Consumer.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ level1, level2, level3, unspecified ]
  dscp_provider_to_consumer:
    description:
    - The target DSCP of Filter Chain For Provider to Consumer.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43,
               CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
    aliases: [ target_provider_to_consumer ]
  description:
    description:
    - Description for the contract subject.
    type: str
    aliases: [ descr ]
  consumer_match:
    description:
    - The match criteria across consumers.
    - The APIC defaults to C(at_least_one) when unset during creation.
    type: str
    choices: [ all, at_least_one, at_most_one, none ]
  provider_match:
    description:
    - The match criteria across providers.
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
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(tenant) and C(contract) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_contract) or M(cisco.aci.aci_oob_contract) modules can be used for this.
seealso:
- module: cisco.aci.aci_contract
- module: cisco.aci.aci_oob_contract
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vz:Subj).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Swetha Chunduri (@schunduri)
"""

EXAMPLES = r"""
- name: Add a new contract subject
  cisco.aci.aci_contract_subject:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: default
    description: test
    reverse_filter: true
    priority: level1
    dscp: unspecified
    state: present
  register: query_result

- name: Add a new subject to an out of band contract
  cisco.aci.aci_contract_subject:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: oob_mgmt_ctr
    contract_type: oob
    subject: default
    description: test
    state: present
  register: query_result

- name: Remove a contract subject
  cisco.aci.aci_contract_subject:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: default
    state: absent
  delegate_to: localhost

- name: Query a contract subject
  cisco.aci.aci_contract_subject:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: default
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all contract subjects
  cisco.aci.aci_contract_subject:
    host: apic
    username: admin
    password: SomeSecretPassword
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
    aci_contract_dscp_spec,
    aci_contract_qos_spec,
)
from ansible_collections.cisco.aci.plugins.module_utils.constants import CONTRACT_CLASS_MAPPING

MATCH_MAPPING = dict(
    all="All",
    at_least_one="AtleastOne",
    at_most_one="AtmostOne",
    none="None",
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        contract=dict(type="str", aliases=["contract_name"]),  # Not required for querying all objects
        contract_type=dict(type="str", choices=["standard", "oob"], default="standard"),
        subject=dict(type="str", aliases=["contract_subject", "name", "subject_name"]),  # Not required for querying all objects
        reverse_filter=dict(type="bool"),
        description=dict(type="str", aliases=["descr"]),
        consumer_match=dict(type="str", choices=["all", "at_least_one", "at_most_one", "none"]),
        provider_match=dict(type="str", choices=["all", "at_least_one", "at_most_one", "none"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
        # default both because of back-worth compatibility and for determining which config to push
        apply_both_direction=dict(type="str", default="both", choices=["both", "one-way"]),
        priority=aci_contract_qos_spec(),
        dscp=aci_contract_dscp_spec(),
        priority_consumer_to_provider=aci_contract_qos_spec(),
        dscp_consumer_to_provider=aci_contract_dscp_spec("consumer_to_provider"),
        priority_provider_to_consumer=aci_contract_qos_spec(),
        dscp_provider_to_consumer=aci_contract_dscp_spec("provider_to_consumer"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["contract", "subject", "tenant"]],
            ["state", "present", ["contract", "subject", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    subject = module.params.get("subject")
    priority = module.params.get("priority")
    dscp = module.params.get("dscp")
    priority_consumer_to_provider = module.params.get("priority_consumer_to_provider")
    dscp_consumer_to_provider = module.params.get("dscp_consumer_to_provider")
    priority_provider_to_consumer = module.params.get("priority_provider_to_consumer")
    dscp_provider_to_consumer = module.params.get("dscp_provider_to_consumer")
    reverse_filter = aci.boolean(module.params.get("reverse_filter"))
    contract = module.params.get("contract")
    contract_type = module.params.get("contract_type")
    description = module.params.get("description")
    consumer_match = module.params.get("consumer_match")
    if consumer_match is not None:
        consumer_match = MATCH_MAPPING.get(consumer_match)
    provider_match = module.params.get("provider_match")
    if provider_match is not None:
        provider_match = MATCH_MAPPING.get(provider_match)
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    name_alias = module.params.get("name_alias")
    direction = module.params.get("apply_both_direction")

    subject_class = "vzSubj"

    base_subject_dict = dict(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class=CONTRACT_CLASS_MAPPING[contract_type]["class"],
            aci_rn=CONTRACT_CLASS_MAPPING[contract_type]["rn"].format(contract),
            module_object=contract,
            target_filter={"name": contract},
        ),
        subclass_2=dict(
            aci_class=subject_class,
            aci_rn="subj-{0}".format(subject),
            module_object=subject,
            target_filter={"name": subject},
        ),
    )

    # start logic to be consistent with GUI to only allow both direction or one-way
    aci.construct_url(
        root_class=base_subject_dict.get("root_class"),
        subclass_1=base_subject_dict.get("subclass_1"),
        subclass_2=base_subject_dict.get("subclass_2"),
        child_classes=["vzInTerm", "vzOutTerm"],
    )
    aci.get_existing()
    direction_options = ["both", "one-way"]
    if state != "query":
        if aci.existing and subject_class in aci.existing[0]:
            direction_options = ["one-way"] if "children" in aci.existing[0][subject_class] else ["both"]
        if direction not in direction_options:
            module.fail_json(msg="Direction is not allowed, valid option is {0}.".format(" or ".join(direction_options)))
        # end logic to be consistent with GUI to only allow both direction or one-way

    if state == "present":
        config = dict(
            name=subject,
            prio=priority,
            revFltPorts=reverse_filter,
            targetDscp=dscp,
            consMatchT=consumer_match,
            provMatchT=provider_match,
            descr=description,
            nameAlias=name_alias,
        )

        child_configs = []
        if direction == "one-way" and (
            len(direction_options) == 2
            or dscp_consumer_to_provider is not None
            or priority_consumer_to_provider is not None
            or dscp_provider_to_consumer is not None
            or priority_provider_to_consumer is not None
        ):
            subj_dn = "uni/tn-{0}/brc-{1}/subj-{2}".format(tenant, contract, subject)
            child_configs = [
                dict(
                    vzInTerm=dict(attributes=dict(dn="{0}/intmnl".format(subj_dn), targetDscp=dscp_consumer_to_provider, prio=priority_consumer_to_provider))
                ),
                dict(
                    vzOutTerm=dict(attributes=dict(dn="{0}/outtmnl".format(subj_dn), targetDscp=dscp_provider_to_consumer, prio=priority_provider_to_consumer))
                ),
            ]

        aci.payload(aci_class=subject_class, class_config=config, child_configs=child_configs)

        aci.get_diff(aci_class=subject_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
