#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_bgp_address_family_context_policy
short_description: Manage BGP address family context policy (bgp:CtxAfPol)
description:
- Manage BGP address family context policies for the Tenants on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  address_family_context_policy:
    description:
    - The name of the BGP address family context policy.
    type: str
    aliases: [ address_family_context_name, name ]
  host_route_leak:
    description:
    - The control state.
    - The option to enable/disable host route leak.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  ebgp_distance:
    description:
    - The administrative distance of eBGP routes.
    - The APIC defaults to C(20) when unset during creation.
    type: int
  ibgp_distance:
    description:
    - The administrative distance of iBGP routes.
    - The APIC defaults to C(200) when unset during creation.
    type: int
  local_distance:
    description:
    - The administrative distance of local routes.
    - The APIC defaults to C(220) when unset during creation.
    type: int
  ebgp_max_ecmp:
    description:
    - The eBGP max-path.
    - The APIC defaults to C(16) when unset during creation.
    type: int
  ibgp_max_ecmp:
    description:
    - The iBGP max-path.
    - The APIC defaults to C(16) when unset during creation.
    type: int
  local_max_ecmp:
    description:
    - The maximum number of equal-cost local paths for redist.
    - The APIC defaults to C(0) when unset during creation.
    - Can not be configured for APIC version 4.2(7s) and prior.
    type: int
  bgp_add_path_capability:
    description:
    - The neighbor system capability.
    - To delete this attribute, pass an empty string.
    - Can not be configured for APIC version 6.0(2h) and prior.
    type: str
    choices: [ receive, send, "" ]
  description:
    description:
    - Description for the BGP protocol profile.
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
  description: More information about the internal APIC class B(bgp:CtxAfPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Create a BGP address family context policy
  cisco.aci.aci_bgp_address_family_context_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    bgp_address_family_context_policy: my_bgp_address_family_context_policy
    host_route_leak: true
    ebgp_distance: 40
    ibgp_distance: 210
    local_distance: 215
    ebgp_max_ecmp: 32
    ibgp_max_ecmp: 32
    local_max_ecmp: 1
    bgp_add_path_capability: receive
    tenant: production
    state: present
  delegate_to: localhost

- name: Delete BGP address family context policy's child
  cisco.aci.aci_bgp_address_family_context_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    bgp_address_family_context_policy: my_bgp_address_family_context_policy
    bgp_add_path_capability: ""
    tenant: production
    state: absent
  delegate_to: localhost

- name: Delete a BGP address family context policy
  cisco.aci.aci_bgp_address_family_context_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    bgp_address_family_context_policy: my_bgp_address_family_context_policy
    tenant: production
    state: absent
  delegate_to: localhost

- name: Query all BGP address family context policies
  cisco.aci.aci_bgp_address_family_context_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific BGP address family context policy
  cisco.aci.aci_bgp_address_family_context_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    bgp_address_family_context_policy: my_bgp_address_family_context_policy
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
        address_family_context_policy=dict(type="str", aliases=["address_family_context_name", "name"]),  # Not required for querying all objects
        host_route_leak=dict(type="bool"),
        ebgp_distance=dict(type="int"),
        ibgp_distance=dict(type="int"),
        local_distance=dict(type="int"),
        ebgp_max_ecmp=dict(type="int"),
        ibgp_max_ecmp=dict(type="int"),
        local_max_ecmp=dict(type="int"),
        bgp_add_path_capability=dict(type="str", choices=["receive", "send", ""]),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["address_family_context_policy", "tenant"]],
            ["state", "present", ["address_family_context_policy", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    address_family_context_policy = module.params.get("address_family_context_policy")
    host_route_leak = aci.boolean(module.params.get("host_route_leak"), "host-rt-leak", "")
    ebgp_distance = module.params.get("ebgp_distance")
    ibgp_distance = module.params.get("ibgp_distance")
    local_distance = module.params.get("local_distance")
    ebgp_max_ecmp = module.params.get("ebgp_max_ecmp")
    ibgp_max_ecmp = module.params.get("ibgp_max_ecmp")
    local_max_ecmp = module.params.get("local_max_ecmp")
    bgp_add_path_capability = module.params.get("bgp_add_path_capability")
    description = module.params.get("description")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    name_alias = module.params.get("name_alias")

    child_classes = []
    if bgp_add_path_capability is not None:
        child_classes.append("bgpCtxAddlPathPol")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="bgpCtxAfPol",
            aci_rn="bgpCtxAfP-{0}".format(address_family_context_policy),
            module_object=address_family_context_policy,
            target_filter={"name": address_family_context_policy},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if bgp_add_path_capability is not None:
            if bgp_add_path_capability == "" and isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("bgpCtxAfPol", {}).get("children", {}):
                    if child.get("bgpCtxAddlPathPol"):
                        child_configs.append(dict(bgpCtxAddlPathPol=dict(attributes=dict(status="deleted"))))
            elif bgp_add_path_capability != "":
                child_configs.append(dict(bgpCtxAddlPathPol=dict(attributes=dict(capability=bgp_add_path_capability))))

        aci.payload(
            aci_class="bgpCtxAfPol",
            class_config=dict(
                name=address_family_context_policy,
                ctrl=host_route_leak,
                eDist=ebgp_distance,
                iDist=ibgp_distance,
                localDist=local_distance,
                maxEcmp=ebgp_max_ecmp,
                maxEcmpIbgp=ibgp_max_ecmp,
                maxLocalEcmp=local_max_ecmp,
                descr=description,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="bgpCtxAfPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
