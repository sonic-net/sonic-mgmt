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
module: aci_route_control_profile
short_description: Manage Route Control Profile (rtctrl:Profile)
description:
- Manage Route Control Profiles on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - The name of an existing L3Out.
    - This will link the created route control profile to the existing L3Out.
    type: str
    aliases: [ l3out_name ]
  route_control_profile:
    description:
    - The name of the route control profile being created.
    type: str
    aliases: [ name, route_control_profile_name ]
  auto_continue:
    description:
    - The option to enable/disable auto-continue.
    type: str
    choices: [ "no", "yes" ]
    default: "no"
  policy_type:
    description:
    - Set the policy type to combinable or global.
    type: str
    choices: [ combinable, global ]
    default: combinable
  description:
    description:
    - The description for the route control profile.
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
- If C(l3out) is used, the C(l3out) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_l3out) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(rtctrl:Profile).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Create a route control profile
  cisco.aci.aci_route_control_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    route_control_profile: prod_route_control_profile
    tenant: production
    l3out: prod_l3out
    auto_continue: "no"
    policy_type: combinable
    state: present
  delegate_to: localhost

- name: Delete a route control profile
  cisco.aci.aci_route_control_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    route_control_profile: prod_route_control_profile
    tenant: production
    l3out: prod_l3out
    state: absent
  delegate_to: localhost

- name: Query all route control profiles
  cisco.aci.aci_route_control_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific route control profile
  cisco.aci.aci_route_control_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
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
        route_control_profile=dict(type="str", aliases=["name", "route_control_profile_name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        auto_continue=dict(type="str", default="no", choices=["no", "yes"]),
        policy_type=dict(type="str", default="combinable", choices=["combinable", "global"]),
        name_alias=dict(type="str"),
        state=dict(type="str", default="present", choices=["present", "absent", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["route_control_profile", "tenant"]],
            ["state", "present", ["route_control_profile", "tenant"]],
        ],
    )

    route_control_profile = module.params.get("route_control_profile")
    description = module.params.get("description")
    auto_continue = module.params.get("auto_continue")
    policy_type = module.params.get("policy_type")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)

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
        )
    else:
        aci.construct_url(
            root_class=tenant_url_config,
            subclass_1=route_control_profile_url_config,
        )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="rtctrlProfile",
            class_config=dict(
                name=route_control_profile,
                descr=description,
                autoContinue=auto_continue,
                type=policy_type,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="rtctrlProfile")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
