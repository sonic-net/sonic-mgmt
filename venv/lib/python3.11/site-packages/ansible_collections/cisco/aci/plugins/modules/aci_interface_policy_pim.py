#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_pim
short_description: Manage Protocol-Independent Multicast (PIM) interface policies (pim:IfPol)
description:
- Manage Protocol Independent Multicast interface policies for Tenants on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing Tenant.
    type: str
    aliases: [ tenant_name ]
  pim:
    description:
    - The PIM interface policy name.
    - The name cannot be changed after the object has been created.
    type: str
    aliases: [ pim_interface_policy, name ]
  authentication_key:
    description:
    - The authentication key.
    type: str
    aliases: [ auth_key ]
  authentication_type:
    description:
    - The authentication type.
    type: str
    choices: [ none, md5_hmac ]
    aliases: [ auth_type ]
  control_state:
    description:
    - The PIM interface policy control state.
    - 'This is a list of one or more of the following controls:'
    - C(multicast_domain_boundary) -- Boundary of Multicast domain.
    - C(strict_rfc_compliant) -- Only listen to PIM protocol packets.
    - C(passive) -- Do not send/receive PIM protocol packets.
    type: list
    elements: str
    choices: [ multicast_domain_boundary, strict_rfc_compliant, passive ]
  designated_router_delay:
    description:
    - The PIM designated router delay.
    - Accepted values range between C(1) and C(65535).
    - The APIC defaults to C(3) when unset during creation.
    type: int
    aliases: [ delay ]
  designated_router_priority:
    description:
    - The PIM designated router priority.
    - Accepted values range between C(1) and C(4294967295).
    - The APIC defaults to C(1) when unset during creation.
    type: int
    aliases: [ prio ]
  hello_interval:
    description:
    - The time interval in seconds between hello packets that PIM sends on the interface.
    - The smaller the hello interval, the faster topological changes will be detected, but more routing traffic will ensue.
    - Accepted values range between C(1) and C(18724286).
    - The APIC defaults to C(30000) when unset during creation.
    type: int
  join_prune_interval:
    description:
    - The join prune interval in seconds.
    - Accepted values range between C(60) and C(65520).
    - The APIC defaults to C(60) when unset during creation.
    type: int
    aliases: [ jp_interval ]
  inbound_join_prune_filter_policy:
    description:
    - The interface-level inbound join/prune filter policy.
    - The M(cisco.aci.aci_pim_route_map_policy) can be used for this.
    - To delete it, pass an empty string.
    type: str
    aliases: [ inbound_filter ]
  outbound_join_prune_filter_policy:
    description:
    - The interface-level outbound join/prune filter policy.
    - The M(cisco.aci.aci_pim_route_map_policy) can be used for this.
    - To delete it, pass an empty string.
    type: str
    aliases: [ outbound_filter ]
  neighbor_filter_policy:
    description:
    - The Interface-level neighbor filter policy.
    - The M(cisco.aci.aci_pim_route_map_policy) can be used for this.
    - To delete it, pass an empty string.
    type: str
    aliases: [ neighbor_filter ]
  description:
    description:
    - The description of the PIM interface policy.
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
- module: cisco.aci.aci_pim_route_map_policy
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(pim:IfPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Create a PIM interface policy
  cisco.aci.aci_interface_policy_pim:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    pim: my_pim_policy
    control_state: [multicast_domain_boundary, strict_rfc_compliant]
    designated_router_delay: 10
    designated_router_priority: tens_of_micro
    hello_interval: 5
    join_prune_interval: 15
    inbound_join_prune_filter_policy: my_pim_route_map_policy_1
    outbound_join_prune_filter_policy: my_pim_route_map_policy_2
    neighbor_filter_policy: my_pim_route_map_policy_3
    state: present
  delegate_to: localhost

- name: Query a PIM interface policy
  cisco.aci.aci_interface_policy_pim:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    pim: my_pim_policy
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all PIM interface policies in tenant production
  cisco.aci.aci_interface_policy_pim:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a PIM interface policy
  cisco.aci.aci_interface_policy_pim:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    pim: my_pim_policy
    state: present
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible_collections.cisco.aci.plugins.module_utils.constants import (
    MATCH_PIM_INTERFACE_POLICY_CONTROL_STATE_MAPPING,
    MATCH_PIM_INTERFACE_POLICY_AUTHENTICATION_TYPE_MAPPING,
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        pim=dict(type="str", aliases=["pim_interface_policy", "name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        authentication_key=dict(type="str", aliases=["auth_key"], no_log=True),
        authentication_type=dict(type="str", choices=["none", "md5_hmac"], aliases=["auth_type"]),
        control_state=dict(type="list", elements="str", choices=["multicast_domain_boundary", "strict_rfc_compliant", "passive"]),
        designated_router_delay=dict(type="int", aliases=["delay"]),
        designated_router_priority=dict(type="int", aliases=["prio"]),
        hello_interval=dict(type="int"),
        join_prune_interval=dict(type="int", aliases=["jp_interval"]),
        inbound_join_prune_filter_policy=dict(type="str", aliases=["inbound_filter"]),
        outbound_join_prune_filter_policy=dict(type="str", aliases=["outbound_filter"]),
        neighbor_filter_policy=dict(type="str", aliases=["neighbor_filter"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["pim", "tenant"]],
            ["state", "present", ["pim", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    pim = module.params.get("pim")
    authentication_key = module.params.get("authentication_key")
    authentication_type = MATCH_PIM_INTERFACE_POLICY_AUTHENTICATION_TYPE_MAPPING.get(module.params.get("authentication_type"))
    description = module.params.get("description")
    name_alias = module.params.get("name_alias")
    state = module.params.get("state")

    designated_router_delay = module.params.get("designated_router_delay")
    if designated_router_delay is not None and designated_router_delay not in range(1, 65536):
        module.fail_json(msg="Parameter 'designated_router_delay' is only valid in range between 1 and 65535.")

    designated_router_priority = module.params.get("designated_router_priority")
    if designated_router_priority is not None and designated_router_priority not in range(1, 4294967296):
        module.fail_json(msg="Parameter 'designated_router_priority' is only valid in range between 1 and 4294967295.")

    hello_interval = module.params.get("hello_interval")
    if hello_interval is not None and hello_interval not in range(1, 18724287):
        module.fail_json(msg="Parameter 'hello_interval' is only valid in range between 1 and 18724286.")

    join_prune_interval = module.params.get("join_prune_interval")
    if join_prune_interval is not None and join_prune_interval not in range(60, 65521):
        module.fail_json(msg="Parameter 'join_prune_interval' is only valid in range between 60 and 65520.")

    if module.params.get("control_state"):
        control_state = ",".join([MATCH_PIM_INTERFACE_POLICY_CONTROL_STATE_MAPPING.get(v) for v in module.params.get("control_state")])
    else:
        control_state = None

    child_classes = dict(
        pimJPInbFilterPol=module.params.get("inbound_join_prune_filter_policy"),
        pimJPOutbFilterPol=module.params.get("outbound_join_prune_filter_policy"),
        pimNbrFilterPol=module.params.get("neighbor_filter_policy"),
    )

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="pimIfPol",
            aci_rn="pimifpol-{0}".format(pim),
            module_object=pim,
            target_filter={"name": pim},
        ),
        child_classes=list(child_classes.keys()),
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        for class_name, class_input in child_classes.items():
            if class_input is not None:
                if class_input == "" and isinstance(aci.existing, list) and len(aci.existing) > 0:
                    for child in aci.existing[0].get("pimIfPol", {}).get("children", {}):
                        if child.get(class_name):
                            child_configs.append(dict([(class_name, dict(attributes=dict(status="deleted")))]))
                elif class_input != "":
                    child_configs.append(
                        dict(
                            [
                                (
                                    class_name,
                                    dict(
                                        attributes=dict(),
                                        children=[
                                            dict(
                                                rtdmcRsFilterToRtMapPol=dict(
                                                    attributes=dict(
                                                        tDn="uni/tn-{0}/rtmap-{1}".format(tenant, class_input),
                                                    ),
                                                )
                                            )
                                        ],
                                    ),
                                )
                            ]
                        )
                    )

        aci.payload(
            aci_class="pimIfPol",
            class_config=dict(
                name=pim,
                descr=description,
                authKey=authentication_key,
                authT=authentication_type,
                ctrl=control_state,
                drDelay=designated_router_delay,
                drPrio=designated_router_priority,
                helloItvl=hello_interval,
                jpInterval=join_prune_interval,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="pimIfPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
