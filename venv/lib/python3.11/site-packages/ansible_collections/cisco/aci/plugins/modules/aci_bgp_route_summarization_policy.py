#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_bgp_route_summarization_policy
short_description: Manage BGP route summarization policy (bgp:RtSummPol)
description:
- Manage BGP route summarization policies for the Tenants on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  route_summarization_policy:
    description:
    - The name of the BGP route summarization policy.
    type: str
    aliases: [ route_summarization_policy_name, name ]
  address_type_af_control:
    description:
    - The Ucast/Mcast address type AF control.
    - The APIC defaults to C(af-ucast) when unset during creation.
    - Can not be configured for APIC version 4.2(7s) or prior.
    type: list
    elements: str
    choices: [ af-label-ucast, af-ucast, af-mcast ]
    aliases: [ address_type_control ]
  control_state:
    description:
    - The summary control.
    - The C(summary_only) option can not be configured for APIC version 4.2(7s) or prior.
    type: list
    elements: str
    choices: [ as-set, summary-only ]
    aliases: [ summary_control, control ]
  description:
    description:
    - Description for the BGP route summarization policy.
    type: str
    aliases: [ descr ]
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
- cisco.aci.owner

notes:
- The C(tenant) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(bgp:RtSummPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Create a BGP route summarization policy
  cisco.aci.aci_bgp_route_summarization_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    route_summarization_policy: my_route_summarization_policy
    address_type_af_control: [af-mcast, af-ucast]
    control_state: [as-set, summary-only]
    tenant: production
    state: present
  delegate_to: localhost

- name: Delete a BGP route summarization policy
  cisco.aci.aci_bgp_route_summarization_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    route_summarization_policy: my_route_summarization_policy
    tenant: production
    state: absent
  delegate_to: localhost

- name: Query all BGP route summarization policies
  cisco.aci.aci_bgp_route_summarization_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific BGP route summarization policy
  cisco.aci.aci_bgp_route_summarization_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    route_summarization_policy: my_route_summarization_policy
    tenant: production
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        route_summarization_policy=dict(type="str", aliases=["route_summarization_policy_name", "name"]),  # Not required for querying all objects
        address_type_af_control=dict(type="list", elements="str", choices=["af-label-ucast", "af-ucast", "af-mcast"], aliases=["address_type_control"]),
        control_state=dict(type="list", elements="str", choices=["as-set", "summary-only"], aliases=["summary_control", "control"]),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["route_summarization_policy", "tenant"]],
            ["state", "present", ["route_summarization_policy", "tenant"]],
        ],
    )

    route_summarization_policy = module.params.get("route_summarization_policy")
    address_type_af_control = ",".join(module.params.get("address_type_af_control")) if module.params.get("address_type_af_control") else None
    control_state = ",".join(module.params.get("control_state")) if module.params.get("control_state") else None
    description = module.params.get("description")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="bgpRtSummPol",
            aci_rn="bgprtsum-{0}".format(route_summarization_policy),
            module_object=route_summarization_policy,
            target_filter={"name": route_summarization_policy},
        ),
    )

    aci.get_existing()

    if state == "present":
        class_config = dict(
            name=route_summarization_policy,
            ctrl=control_state,
            descr=description,
            nameAlias=name_alias,
        )

        if address_type_af_control is not None:
            class_config.update(dict(addrTCtrl=address_type_af_control))

        aci.payload(
            aci_class="bgpRtSummPol",
            class_config=class_config,
        )

        aci.get_diff(aci_class="bgpRtSummPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
