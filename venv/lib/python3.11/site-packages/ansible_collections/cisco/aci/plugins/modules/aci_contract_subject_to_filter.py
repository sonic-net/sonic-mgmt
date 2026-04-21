#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_contract_subject_to_filter
short_description: Bind Contract Subjects to Filters (vz:RsSubjFiltAtt)
description:
- Bind Contract Subjects to Filters on Cisco ACI fabrics.
options:
  contract:
    description:
    - The name of the contract.
    type: str
    aliases: [ contract_name ]
  contract_type:
    description:
    - The type of contract, either standard or Out of Band (oob).
    type: str
    choices: [ standard, oob ]
    default: standard
  filter:
    description:
    - The name of the Filter to bind to the Subject.
    type: str
    aliases: [ filter_name ]
  direction:
    description:
    - The direction of traffic matching for the filter.
    type: str
    default: both
    choices: [ both, consumer_to_provider, provider_to_consumer ]
  action:
    description:
    - The action required when the condition is met.
    - The APIC defaults to C(permit) when unset during creation.
    type: str
    choices: [ deny, permit ]
  priority_override:
    description:
    - Overrides the filter priority for the a single applied filter.
    type: str
    choices: [ default, level1, level2, level3 ]
  directives:
    description:
    - Determines if the binding should be set to log.
    - The APIC defaults to C(none) when unset during creation.
    type: str
    choices: [ log, no_stats, none ]
    aliases: [ log, directive]
  subject:
    description:
    - The name of the Contract Subject.
    type: str
    aliases: [ contract_subject, subject_name ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  tenant:
    description:
    - The name of the tenant.
    type: str
    aliases: [ tenant_name ]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(tenant), C(contract), C(subject), and C(filter_name) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_contract), M(cisco.aci.aci_contract_subject), and M(cisco.aci.aci_filter) modules can be used for these.
seealso:
- module: cisco.aci.aci_contract_subject
- module: cisco.aci.aci_filter
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vz:RsSubjFiltAtt).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
"""

EXAMPLES = r"""
- name: Add a new contract subject to filer binding
  cisco.aci.aci_contract_subject_to_filter:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: test
    filter: '{{ filter }}'
    log: '{{ log }}'
    state: present
  delegate_to: localhost

- name: Remove an existing contract subject to filter binding
  cisco.aci.aci_contract_subject_to_filter:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: test
    filter: '{{ filter }}'
    log: '{{ log }}'
    state: present
  delegate_to: localhost

- name: Query a specific contract subject to filter binding
  cisco.aci.aci_contract_subject_to_filter:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: test
    filter: '{{ filter }}'
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all contract subject to filter bindings
  cisco.aci.aci_contract_subject_to_filter:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: test
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import CONTRACT_CLASS_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        contract=dict(type="str", aliases=["contract_name"]),  # Not required for querying all objects
        contract_type=dict(type="str", choices=["standard", "oob"], default="standard"),
        filter=dict(type="str", aliases=["filter_name"]),  # Not required for querying all objects
        subject=dict(type="str", aliases=["contract_subject", "subject_name"]),  # Not required for querying all objects
        # default both because of back-worth compatibility and for determining which config to push
        direction=dict(type="str", default="both", choices=["both", "consumer_to_provider", "provider_to_consumer"]),
        action=dict(type="str", choices=["deny", "permit"]),
        # named directives instead of log/directive for readability of code, aliases and input "none are kept for back-worth compatibility
        directives=dict(type="str", choices=["log", "no_stats", "none"], aliases=["log", "directive"]),
        priority_override=dict(type="str", choices=["default", "level1", "level2", "level3"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["contract", "filter", "subject", "tenant"]],
            ["state", "present", ["contract", "filter", "subject", "tenant"]],
        ],
    )

    contract = module.params.get("contract")
    contract_type = module.params.get("contract_type")
    filter_name = module.params.get("filter")
    # "none" is kept because of back-worth compatibility, could be deleted and keep only None
    directives = "" if (module.params.get("directives") is None or module.params.get("directives") == "none") else module.params.get("directives")
    subject = module.params.get("subject")
    direction = module.params.get("direction")
    action = module.params.get("action")
    priority_override = module.params.get("priority_override")
    tenant = module.params.get("tenant")
    state = module.params.get("state")

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
            aci_class="vzSubj",
            aci_rn="subj-{0}".format(subject),
            module_object=subject,
            target_filter={"name": subject},
        ),
    )

    aci = ACIModule(module)

    # start logic to be consistent with GUI to only allow both direction or a one-way connection
    aci.construct_url(
        root_class=base_subject_dict.get("root_class"),
        subclass_1=base_subject_dict.get("subclass_1"),
        subclass_2=base_subject_dict.get("subclass_2"),
        child_classes=["vzInTerm", "vzOutTerm"],
    )
    aci.get_existing()
    direction_options = ["both"]
    if aci.existing:
        direction_options = ["consumer_to_provider", "provider_to_consumer"] if "children" in aci.existing[0]["vzSubj"] else ["both"]

    if state != "query" and direction not in direction_options:
        module.fail_json(msg="Direction is not allowed, valid option is {0}.".format(" or ".join(direction_options)))
    # end logic to be consistent with GUI to only allow both direction or a one-way connection

    if direction == "both":
        filter_class = "vzRsSubjFiltAtt"
        # dict unpacking with **base_subject_dict raises syntax error in python2.7 thus dict lookup
        aci.construct_url(
            root_class=base_subject_dict.get("root_class"),
            subclass_1=base_subject_dict.get("subclass_1"),
            subclass_2=base_subject_dict.get("subclass_2"),
            subclass_3=dict(
                aci_class=filter_class,
                aci_rn="rssubjFiltAtt-{0}".format(filter_name),
                module_object=filter_name,
                target_filter=dict(tnVzFilterName=filter_name),
            ),
        )
    else:
        term_class, term = ("vzInTerm", "intmnl") if direction == "consumer_to_provider" else ("vzOutTerm", "outtmnl")
        filter_class = "vzRsFiltAtt"
        # dict unpacking with **base_subject_dict raises syntax error in python2.7 thus dict lookup
        aci.construct_url(
            root_class=base_subject_dict.get("root_class"),
            subclass_1=base_subject_dict.get("subclass_1"),
            subclass_2=base_subject_dict.get("subclass_2"),
            subclass_3=dict(aci_class=term_class, aci_rn=term),
            child_classes=[filter_class],
        )

    aci.get_existing()

    if state == "present":
        config = dict(tnVzFilterName=filter_name, directives=directives, action=action, priorityOverride=priority_override)
        if direction == "both":
            aci.payload(aci_class=filter_class, class_config=config)
            aci.get_diff(aci_class=filter_class)
        else:
            child_config = [dict(vzRsFiltAtt=dict(attributes=config))]
            aci.payload(aci_class=term_class, class_config=dict(), child_configs=child_config)
            aci.get_diff(aci_class=term_class)
        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    if direction == "both":
        aci.exit_json()
    else:
        # filter the output of current/previous to tnVzFilterName only since existing consist full vzInTerm/vzOutTerm
        def filter_result(input_list, name):
            return [
                {key: filter_entry}
                for entry in input_list
                if "children" in entry[term_class]
                for children in entry[term_class]["children"]
                for key, filter_entry in children.items()
                if filter_entry["attributes"]["tnVzFilterName"] == name
            ]

        # pass function to
        filter_existing = (filter_result, filter_name)
        aci.exit_json(filter_existing)


if __name__ == "__main__":
    main()
