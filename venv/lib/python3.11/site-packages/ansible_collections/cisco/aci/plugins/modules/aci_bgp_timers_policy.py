#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_bgp_timers_policy
short_description: Manage BGP timers policy (bgp:CtxPol)
description:
- Manage BGP timers policies for the Tenants on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  bgp_timers_policy:
    description:
    - The name of the BGP timers policy.
    type: str
    aliases: [ bgp_timers_policy_name, name ]
  graceful_restart_controls:
    description:
    - The property to determine whether the entity functions only as a graceful restart helper or whether graceful restart is enabled completely.
    - The graceful restart helper option configures the local BGP router to support the graceful restart of a remote BGP peer.
    - The complete graceful restart option allows BGP graceful restart to be enabled or disable for an individual neighbor.
    - The APIC defaults to C(helper) when unset during creation.
    type: str
    choices: [ helper, complete ]
  hold_interval:
    description:
    - The time period to wait before declaring the neighbor device down.
    - The APIC defaults to C(180) when unset during creation.
    type: int
  keepalive_interval:
    description:
    - The interval time between sending keepalive messages.
    - The APIC defaults to C(60) when unset during creation.
    type: int
  max_as_limit:
    description:
    - The maximum AS limit, to discard routes that have excessive AS numbers.
    - The APIC defaults to C(0) when unset during creation.
    type: int
  stale_interval:
    description:
    - The maximum time that BGP keeps stale routes from the restarting BGP peer.
    - The APIC defaults to C(default) which is equal to 300 sec when unset during creation.
    type: int
  description:
    description:
    - Description for the BGP timers policy.
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
  description: More information about the internal APIC class B(bgp:CtxPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Create a BGP timers policy
  cisco.aci.aci_bgp_timers_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    bgp_timers_policy: my_bgp_timers_policy
    graceful_restart_controls: complete
    hold_interval: 360
    keepalive_interval: 120
    max_as_limit: 1
    stale_interval: 600
    tenant: production
    state: present
  delegate_to: localhost

- name: Delete a BGP timers policy
  cisco.aci.aci_bgp_timers_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    bgp_timers_policy: my_bgp_timers_policy
    tenant: production
    state: absent
  delegate_to: localhost

- name: Query all BGP timers policies
  cisco.aci.aci_bgp_timers_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific BGP timers policy
  cisco.aci.aci_bgp_timers_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    bgp_timers_policy: my_bgp_timers_policy
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import MATCH_GRACEFUL_RESTART_CONTROLS_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        bgp_timers_policy=dict(type="str", aliases=["bgp_timers_policy_name", "name"]),  # Not required for querying all objects
        graceful_restart_controls=dict(type="str", choices=["helper", "complete"]),
        hold_interval=dict(type="int"),
        keepalive_interval=dict(type="int"),
        max_as_limit=dict(type="int"),
        stale_interval=dict(type="int"),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["bgp_timers_policy", "tenant"]],
            ["state", "present", ["bgp_timers_policy", "tenant"]],
        ],
    )

    bgp_timers_policy = module.params.get("bgp_timers_policy")
    graceful_restart_controls = MATCH_GRACEFUL_RESTART_CONTROLS_MAPPING.get(module.params.get("graceful_restart_controls"))
    hold_interval = module.params.get("hold_interval")
    keepalive_interval = module.params.get("keepalive_interval")
    max_as_limit = module.params.get("max_as_limit")
    stale_interval = module.params.get("stale_interval")
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
            aci_class="bgpCtxPol",
            aci_rn="bgpCtxP-{0}".format(bgp_timers_policy),
            module_object=bgp_timers_policy,
            target_filter={"name": bgp_timers_policy},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="bgpCtxPol",
            class_config=dict(
                name=bgp_timers_policy,
                grCtrl=graceful_restart_controls,
                holdIntvl=hold_interval,
                kaIntvl=keepalive_interval,
                maxAsLimit=max_as_limit,
                staleIntvl=stale_interval,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="bgpCtxPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
