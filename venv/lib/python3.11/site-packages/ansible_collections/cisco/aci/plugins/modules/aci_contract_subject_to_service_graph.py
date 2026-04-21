#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_contract_subject_to_service_graph
short_description: Bind contract subject to service graph (vz:RsSubjGraphAtt)
description:
- Bind contract subject to service graph.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
  contract:
    description:
    - The name of the contract.
    type: str
  subject:
    description:
    - The contract subject name.
    type: str
  service_graph:
    description:
    - The service graph name.
    type: str
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

author:
- Marcel Zehnder (@maercu)
"""

EXAMPLES = r"""
- name: Add a new contract subject to service graph binding
  cisco.aci.aci_contract_subject_to_service_graph:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: test
    service_graph: '{{ service_graph }}'
    state: present
  delegate_to: localhost
- name: Remove an existing contract subject to service graph binding
  cisco.aci.aci_contract_subject_to_service_graph:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: test
    service_graph: '{{ service_graph }}'
    state: absent
  delegate_to: localhost
- name: Query a specific contract subject to service graph binding
  cisco.aci.aci_contract_subject_to_service_graph:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    contract: web_to_db
    subject: test
    service_graph: '{{ service_graph }}'
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str"),
        contract=dict(type="str"),
        subject=dict(type="str"),
        service_graph=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["contract", "service_graph", "subject", "tenant"]],
            ["state", "present", ["contract", "service_graph", "subject", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    contract = module.params.get("contract")
    subject = module.params.get("subject")
    service_graph = module.params.get("service_graph")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(aci_class="vzBrCP", aci_rn="brc-{0}".format(contract), module_object=contract, target_filter={"name": contract}),
        subclass_2=dict(aci_class="vzSubj", aci_rn="subj-{0}".format(subject), module_object=subject, target_filter={"name": subject}),
        subclass_3=dict(aci_class="vzRsSubjGraphAtt", aci_rn="rsSubjGraphAtt", module_object=service_graph, target_filter={"name": service_graph}),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(aci_class="vzRsSubjGraphAtt", class_config=dict(tnVnsAbsGraphName=service_graph))

        aci.get_diff(aci_class="vzRsSubjGraphAtt")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
