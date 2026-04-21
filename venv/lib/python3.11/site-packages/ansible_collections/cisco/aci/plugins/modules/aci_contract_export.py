#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_contract_export
short_description: Manage contract interfaces (vz:CPIf)
description:
- Manage Contract interfaces on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the contract interface.
    type: str
    aliases: [ interface_name ]
  destination_tenant:
    description:
    - The The tenant associated with the contract interface.
    type: str
  description:
    description:
    - Description for the contract interface.
    type: str
    aliases: [ descr ]
  tenant:
    description:
    - The name of the tenant hosting the contract to export.
    type: str
    aliases: [ tenant_name ]
  contract:
    description:
    - The name of the contract to export.
    type: str
    aliases: [ contract_name ]
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

seealso:
- module: cisco.aci.aci_contract
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vz:BrCP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Marcel Zehnder (@maercu)
"""

EXAMPLES = r"""
- name: Create a new contract interface
  cisco.aci.aci_contract_export:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: contractintf
    destination_tenant: tndest
    tenant: tnsrc
    contract: web_to_db
    state: present
  delegate_to: localhost

- name: Remove an existing contract interface
  cisco.aci.aci_contract_export:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: contractintf
    destination_tenant: tndest
    tenant: tnsrc
    contract: web_to_db
    state: absent
  delegate_to: localhost

- name: Query a specific contract interface
  cisco.aci.aci_contract_export:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: contractintf
    destination_tenant: tndest
    tenant: tnsrc
    contract: web_to_db
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all contract interfaces
  cisco.aci.aci_contract_export:
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["interface_name"]),
        destination_tenant=dict(type="str"),
        description=dict(type="str", aliases=["descr"]),
        tenant=dict(type="str", aliases=["tenant_name"]),
        contract=dict(type="str", aliases=["contract_name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "destination_tenant", "tenant", "contract"]],
            ["state", "present", ["name", "destination_tenant", "tenant", "contract"]],
        ],
    )

    name = module.params.get("name")
    destination_tenant = module.params.get("destination_tenant")
    description = module.params.get("description")
    tenant = module.params.get("tenant")
    contract = module.params.get("contract")
    state = module.params.get("state")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(destination_tenant),
            module_object=destination_tenant,
            target_filter={"name": destination_tenant},
        ),
        subclass_1=dict(
            aci_class="vzCPIf",
            aci_rn="cif-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=["vzRsIf"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = [dict(vzRsIf=dict(attributes=dict(tDn="uni/tn-{0}/brc-{1}".format(tenant, contract))))]

        aci.payload(aci_class="vzCPIf", class_config=dict(name=name, descr=description), child_configs=child_configs)

        aci.get_diff(aci_class="vzCPIf")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
