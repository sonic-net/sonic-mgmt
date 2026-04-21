#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}


DOCUMENTATION = r"""
---
module: aci_epg_to_contract_interface
short_description: Bind EPGs to Consumed Contracts Interface (fv:RsConsIf)

description:
- Bind EPGs to Consumed Contracts Interface on Cisco ACI fabrics.
notes:
- The C(tenant), C(app_profile), C(EPG), and C(Contract Interface) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_ap), M(cisco.aci.aci_epg), and M(cisco.aci.aci_contract_export) modules can be used for this.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  ap:
    description:
    - Name of an existing application profile, that will contain the EPGs.
    type: str
    aliases: [ app_profile, app_profile_name ]
  epg:
    description:
    - The name of the end point group.
    type: str
    aliases: [ epg_name ]
  contract_interface:
    description:
    - Name of the Contract interface, which is the contract with a "Global" scope which is exported to the tenant.
    type: str
    aliases: [ contract_interface_name ]
  priority:
    description:
    - QoS class.
    - The default value of QoS is C(unspecified) during the creation.
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
- module: cisco.aci.aci_ap
- module: cisco.aci.aci_epg
- module: cisco.aci.aci_contract_export
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(fv:RsCons) and B(fv:RsProv).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sabari Jaganathan (@sajagana)
"""
EXAMPLES = r"""
- name: Add a new consumed contract interface to EPG
  cisco.aci.aci_epg_to_contract_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    contract_interface: anstest_http
    state: present
  delegate_to: localhost

- name: Remove an existing consumed contract interface
  cisco.aci.aci_epg_to_contract_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    contract_interface: anstest_http
    state: absent
  delegate_to: localhost

- name: Query a specific consumed contract interface
  cisco.aci.aci_epg_to_contract_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    contract_interface: anstest_http
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all  consumed contract interfaces
  cisco.aci.aci_epg_to_contract_interface:
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),  # Not required for querying all objects
        epg=dict(type="str", aliases=["epg_name"]),  # Not required for querying all objects
        contract_interface=dict(type="str", aliases=["contract_interface_name"]),  # Not required for querying all objects
        priority=dict(type="str", choices=["level1", "level2", "level3", "level4", "level5", "level6", "unspecified"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "ap", "epg", "contract_interface"]],
            ["state", "present", ["tenant", "ap", "epg", "contract_interface"]],
        ],
    )

    tenant = module.params.get("tenant")
    ap = module.params.get("ap")
    epg = module.params.get("epg")
    contract_interface = module.params.get("contract_interface")
    priority = module.params.get("priority")
    state = module.params.get("state")

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
            aci_class="fvRsConsIf",
            aci_rn="rsconsIf-{0}".format(contract_interface),
            module_object=contract_interface,
            target_filter={"name": contract_interface},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fvRsConsIf",
            class_config=dict(
                prio=priority,
                tnVzCPIfName=contract_interface,
            ),
        )

        aci.get_diff(aci_class="fvRsConsIf")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
