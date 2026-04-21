#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Eric Girard <@netgirard>
# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "certified",
}

DOCUMENTATION = r"""
---
module: aci_access_spine_switch_selector
short_description: Manage Fabric Access Policy Spine Switch Port Selectors (infra:SpineS)
description:
- Manage Fabric Access Policy Spine Switch Port Selectors on Cisco ACI fabrics.
options:
  spine_switch_profile:
    description:
    - The name of the Fabric access policy spine switch profile.
    type: str
    aliases: [ spine_switch_profile_name, switch_profile, switch_profile_name ]
  spine_switch_selector:
    description:
    -  The name of the Fabric access spine switch port selector.
    type: str
    aliases: [ name, spine_switch_selector_name, switch_selector, switch_selector_name, access_port_selector, access_port_selector_name  ]
  description:
    description:
    - The description for the spine switch port selector.
    type: str
  policy_group:
    description:
    - The name of the fabric access policy group to be associated with the spine switch port selector.
    type: str
    aliases: [ policy_group_name ]
  selector_type:
    description:
    - The host port selector type.
    - If using a port block to specify range of switches, the type must be set to C(range).
    type: str
    choices: [ all, range ]
    aliases: [ type ]
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

notes:
- The I(spine_switch_profile) must exist before using this module in your playbook.
  The M(cisco.aci.aci_access_spine_switch_profile) module can be used for this.
- If a I(policy_group) is used, it must exist before using this module in your playbook.
  The M(cisco.aci.aci_switch_policy_group) module can be used for this.
seealso:
- module: cisco.aci.aci_access_spine_switch_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:SpineS) and B(infra:RsAccNodePGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Eric Girard (@netgirard)
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a switch policy spine profile selector (with policy group)
  cisco.aci.aci_access_spine_switch_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    spine_switch_profile: sw_name
    spine_switch_selector: spine_selector_name
    selector_type: range
    policy_group: somepolicygroupname
    state: present
  delegate_to: localhost

- name: Query a switch policy spine profile selector
  cisco.aci.aci_access_spine_switch_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    spine_switch_profile: sw_name
    spine_switch_selector: spine_selector_name
    selector_type: range
    state: query
  delegate_to: localhost

- name: Query all switch policy spine profile selectors
  cisco.aci.aci_access_spine_switch_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove a switch policy spine profile selector
  cisco.aci.aci_access_spine_switch_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    spine_switch_profile: sw_name
    spine_switch_selector: spine_selector_name
    selector_type: range
    state: absent
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import MATCH_ACCESS_POLICIES_SELECTOR_TYPE


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        spine_switch_profile=dict(type="str", aliases=["spine_switch_profile_name", "switch_profile", "switch_profile_name"]),
        spine_switch_selector=dict(
            type="str",
            aliases=[
                "name",
                "spine_switch_selector_name",
                "switch_selector",
                "switch_selector_name",
                "access_port_selector",
                "access_port_selector_name",
            ],
        ),  # Not required for querying all objects
        description=dict(type="str"),
        policy_group=dict(type="str", aliases=["policy_group_name"]),
        selector_type=dict(type="str", choices=list(MATCH_ACCESS_POLICIES_SELECTOR_TYPE.keys()), aliases=["type"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["spine_switch_profile", "spine_switch_selector", "selector_type"]],
            ["state", "present", ["spine_switch_profile", "spine_switch_selector", "selector_type"]],
        ],
    )

    spine_switch_profile = module.params.get("spine_switch_profile")
    spine_switch_selector = module.params.get("spine_switch_selector")
    description = module.params.get("description")
    policy_group = module.params.get("policy_group")
    selector_type = MATCH_ACCESS_POLICIES_SELECTOR_TYPE.get(module.params.get("selector_type"))
    state = module.params.get("state")

    child_configs = []
    if policy_group is not None:
        child_configs.append(dict(infraRsSpineAccNodePGrp=dict(attributes=dict(tDn="uni/infra/funcprof/spaccnodepgrp-{0}".format(policy_group)))))

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="infraInfra",
            aci_rn="infra",
        ),
        subclass_1=dict(
            aci_class="infraSpineP",
            aci_rn="spprof-{0}".format(spine_switch_profile),
            module_object=spine_switch_profile,
            target_filter={"name": spine_switch_profile},
        ),
        subclass_2=dict(
            aci_class="infraSpineS",
            aci_rn="spines-{0}-typ-{1}".format(spine_switch_selector, selector_type),
            module_object=spine_switch_selector,
            target_filter={"name": spine_switch_selector},
        ),
        child_classes=["infraRsSpineAccNodePGrp"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="infraSpineS",
            class_config=dict(
                descr=description,
                name=spine_switch_selector,
                type=selector_type,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="infraSpineS")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
