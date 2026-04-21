#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_access_spine_interface_selector
short_description: Manage Fabric Access Policy Spine Interface Port Selectors (infra:SHPortS)
description:
- Manage Fabric Access Policy Spine Interface Port Selectors on Cisco ACI fabrics.
- This selector is used for applying infrastructure policies on selected ports.
options:
  spine_interface_profile:
    description:
    - The name of the Fabric access policy spine interface profile.
    type: str
    aliases: [ spine_interface_profile_name, interface_profile, interface_profile_name ]
  spine_interface_selector:
    description:
    -  The name of the Fabric access spine interface port selector.
    type: str
    aliases: [ name, spine_interface_selector_name, interface_selector, interface_selector_name, access_port_selector, access_port_selector_name  ]
  description:
    description:
    - The description for the spine interface port selector.
    type: str
  policy_group:
    description:
    - The name of the fabric access policy group to be associated with the spine interface port selector.
    type: str
    aliases: [ policy_group_name ]
  selector_type:
    description:
    - The host port selector type.
    - If using a port block to specify range of interfaces, the type must be set to C(range).
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
- The I(spine_interface_profile) must exist before using this module in your playbook.
  The M(cisco.aci.aci_access_spine_interface_profile) module can be used for this.
- If a I(policy_group) is used, it must exist before using this module in your playbook.
  The M(cisco.aci.aci_interface_policy_spine_policy_group) module can be used for this.
seealso:
- module: cisco.aci.aci_access_port_block_to_access_port
- module: cisco.aci.aci_interface_policy_spine_policy_group
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:SHPortS) and B(infra:RsSpAccGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a new access spine interface selector
  cisco.aci.aci_access_spine_interface_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    spine_interface_profile: my_access_spine_interface_profile
    spine_interface_selector: my_access_spine_interface_selector
    selector_type: range
    policy_group: my_access_spine_interface_policy_group
    state: present
  delegate_to: localhost

- name: Query a specific access spine interface selector under given spine_interface_profile
  cisco.aci.aci_access_spine_interface_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    spine_interface_profile: my_access_spine_interface_profile
    spine_interface_selector: my_access_spine_interface_selector
    selector_type: range
    state: query
  delegate_to: localhost

- name: Query all access spine interface selectors under given spine_interface_profile
  cisco.aci.aci_access_spine_interface_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    spine_interface_profile: my_access_spine_interface_profile
    state: query
  delegate_to: localhost

- name: Query all access spine interface selectors
  cisco.aci.aci_access_spine_interface_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove an access spine interface selector
  cisco.aci.aci_access_spine_interface_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    spine_interface_profile: my_access_spine_interface_profile
    spine_interface_selector: my_access_spine_interface_selector
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
        spine_interface_profile=dict(type="str", aliases=["spine_interface_profile_name", "interface_profile", "interface_profile_name"]),
        spine_interface_selector=dict(
            type="str",
            aliases=[
                "name",
                "spine_interface_selector_name",
                "interface_selector",
                "interface_selector_name",
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
            ["state", "absent", ["spine_interface_profile", "spine_interface_selector", "selector_type"]],
            ["state", "present", ["spine_interface_profile", "spine_interface_selector", "selector_type"]],
        ],
    )

    spine_interface_profile = module.params.get("spine_interface_profile")
    spine_interface_selector = module.params.get("spine_interface_selector")
    description = module.params.get("description")
    policy_group = module.params.get("policy_group")
    selector_type = MATCH_ACCESS_POLICIES_SELECTOR_TYPE.get(module.params.get("selector_type"))
    state = module.params.get("state")

    child_configs = []
    if policy_group is not None:
        child_configs.append(dict(infraRsSpAccGrp=dict(attributes=dict(tDn="uni/infra/funcprof/spaccportgrp-{0}".format(policy_group)))))

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="infraInfra",
            aci_rn="infra",
        ),
        subclass_1=dict(
            aci_class="infraSpAccPortP",
            aci_rn="spaccportprof-{0}".format(spine_interface_profile),
            module_object=spine_interface_profile,
            target_filter={"name": spine_interface_profile},
        ),
        subclass_2=dict(
            aci_class="infraSHPortS",
            aci_rn="shports-{0}-typ-{1}".format(spine_interface_selector, selector_type),
            module_object=spine_interface_selector,
            target_filter={"name": spine_interface_selector},
        ),
        child_classes=["infraRsSpAccGrp"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="infraSHPortS",
            class_config=dict(
                descr=description,
                name=spine_interface_selector,
                type=selector_type,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="infraSHPortS")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
