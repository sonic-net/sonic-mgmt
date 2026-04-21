#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_route_control_context
short_description: Manage Route Control Context (rtctrl:CtxP)
description:
- Manage Route Control Context Policies for the Route Control Profiles on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - The name of an existing L3Out.
    - To use only if the route control profile is linked to an existing L3Out.
    type: str
    aliases: [ l3out_name ]
  route_control_profile:
    description:
    - The name of an existing route control profile.
    type: str
    aliases: [ route_control_profile_name ]
  route_control_context:
    description:
    - The name of the route control context being created.
    type: str
    aliases: [ name, route_control_context_name, context ]
  action:
    description:
    - The action required when the condition is met.
    type: str
    choices: [ deny, permit ]
  action_rule:
    description:
    - The name of the action rule profile to be associated with this route control context.
    - Set the rules for a Route Map.
    type: str
    aliases: [ action_rule_name ]
  match_rule:
    description:
    - The name of the match rule profile to be associated with this route control context.
    - Set the associated Matched rules.
    type: str
    aliases: [ match_rule_name ]
  order:
    description:
    - The order of the route control context.
    - The value range from 0 to 9.
    type: int
  description:
    description:
    - The description for the route control context.
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
- The C(tenant) and the C(route_control_profile) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and the M(cisco.aci.aci_route_control_profile) modules can be used for this.
- If C(l3out) is used, the C(l3out) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_l3out) module can be used for this.
- if C(action_rule) is used, the C(action_rule) used must exist before using this module in your plabook.
  The module M(cisco.aci.aci_tenant_action_rule_profile) can be used for this.
- if C(match_rule) is used, the C(match_rule) used must exist before using this module in your plabook.
  The module M(cisco.aci.aci_match_rule) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_route_control_profile
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_tenant_action_rule_profile
- module: cisco.aci.aci_match_rule
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(rtctrl:CtxP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Create a route context policy
  cisco.aci.aci_route_control_context:
    host: apic
    username: admin
    password: SomeSecretPassword
    route_control_context: prod_route_control_context
    route_control_profile: prod_route_control_profile
    tenant: production
    l3out: prod_l3out
    action: permit
    order: 0
    action_rule: prod_action_rule_profile
    match_rule: prod_match_rule
    state: present
  delegate_to: localhost

- name: Delete a route context policy
  cisco.aci.aci_route_control_context:
    host: apic
    username: admin
    password: SomeSecretPassword
    route_control_context: prod_route_control_context
    route_control_profile: prod_route_control_profile
    tenant: production
    l3out: prod_l3out
    state: absent
  delegate_to: localhost

- name: Query all route context policy
  cisco.aci.aci_route_control_context:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific route context policy
  cisco.aci.aci_route_control_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    route_control_context: prod_route_control_context
    route_control_profile: prod_route_control_profile
    tenant: production
    l3out: prod_l3out
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
                    "ownerauto_continue": ""
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
                    "ownerauto_continue": ""
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
        l3out=dict(type="str", aliases=["l3out_name"]),  # Not required for querying all objects
        route_control_profile=dict(type="str", aliases=["route_control_profile_name"]),  # Not required for querying all objects
        route_control_context=dict(type="str", aliases=["name", "route_control_context_name", "context"]),  # Not required for querying all objects
        match_rule=dict(type="str", aliases=["match_rule_name"]),
        action_rule=dict(type="str", aliases=["action_rule_name"]),
        action=dict(type="str", choices=["deny", "permit"]),
        order=dict(type="int"),
        description=dict(type="str", aliases=["descr"]),
        name_alias=dict(type="str"),
        state=dict(type="str", default="present", choices=["present", "absent", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["route_control_context", "tenant"]],
            ["state", "present", ["route_control_context", "tenant"]],
        ],
    )

    route_control_context = module.params.get("route_control_context")
    description = module.params.get("description")
    action = module.params.get("action")
    order = module.params.get("order")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    route_control_profile = module.params.get("route_control_profile")
    match_rule = module.params.get("match_rule")
    action_rule = module.params.get("action_rule")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)

    child_classes = ["rtctrlRsCtxPToSubjP", "rtctrlScope"]

    tenant_url_config = dict(
        aci_class="fvTenant",
        aci_rn="tn-{0}".format(tenant),
        module_object=tenant,
        target_filter={"name": tenant},
    )

    route_control_profile_url_config = dict(
        aci_class="rtctrlProfile",
        aci_rn="prof-{0}".format(route_control_profile),
        module_object=route_control_profile,
        target_filter={"name": route_control_profile},
    )

    route_control_context_url_config = dict(
        aci_class="rtctrlCtxP",
        aci_rn="ctx-{0}".format(route_control_context),
        module_object=route_control_context,
        target_filter={"name": route_control_context},
    )

    if l3out is not None:
        aci.construct_url(
            root_class=tenant_url_config,
            subclass_1=dict(
                aci_class="l3extOut",
                aci_rn="out-{0}".format(l3out),
                module_object=l3out,
                target_filter={"name": l3out},
            ),
            subclass_2=route_control_profile_url_config,
            subclass_3=route_control_context_url_config,
            child_classes=child_classes,
        )
    else:
        aci.construct_url(
            root_class=tenant_url_config,
            subclass_1=route_control_profile_url_config,
            subclass_2=route_control_context_url_config,
            child_classes=child_classes,
        )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if match_rule is not None:
            child_configs.append({"rtctrlRsCtxPToSubjP": {"attributes": {"tnRtctrlSubjPName": match_rule}}})
        if action_rule is not None:
            child_configs.append(
                {
                    "rtctrlScope": {
                        "attributes": {"descr": ""},
                        "children": [{"rtctrlRsScopeToAttrP": {"attributes": {"tnRtctrlAttrPName": action_rule}}}],
                    }
                }
            )

        aci.payload(
            aci_class="rtctrlCtxP",
            class_config=dict(
                name=route_control_context,
                descr=description,
                action=action,
                order=order,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="rtctrlCtxP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
