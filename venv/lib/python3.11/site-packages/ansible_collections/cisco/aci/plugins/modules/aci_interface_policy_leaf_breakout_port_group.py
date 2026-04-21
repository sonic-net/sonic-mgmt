#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Cindy Zhao <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_leaf_breakout_port_group
short_description: Manage fabric interface policy leaf breakout port group (infra:BrkoutPortGrp)
description:
- Manage fabric interface policy leaf breakout port group on Cisco ACI fabrics.
options:
  breakout_port_group:
    description:
    - Name of the leaf breakout port group to be added/deleted.
    type: str
    aliases: [ name ]
  description:
    description:
    - Description for the leaf breakout port group to be created.
    type: str
    aliases: [ descr ]
  breakout_map:
    description:
    - The mapping of breakout port.
    type: str
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
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:BrkoutPortGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Cindy Zhao (@cizhao)
"""

EXAMPLES = r"""
- name: Create a Leaf Breakout Port Group
  cisco.aci.aci_interface_policy_leaf_breakout_port_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    breakout_port_group: BreakoutPortName
    breakout_map: 10g-4x
    state: present
  delegate_to: localhost

- name: Query all Leaf Breakout Port Groups of type link
  cisco.aci.aci_interface_policy_leaf_breakout_port_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific Leaf Breakout Port Group
  cisco.aci.aci_interface_policy_leaf_breakout_port_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    breakout_port_group: BreakoutPortName
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete an Leaf Breakout Port Group
  cisco.aci.aci_interface_policy_leaf_breakout_port_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    breakout_port_group: BreakoutPortName
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


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        breakout_port_group=dict(type="str", aliases=["name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        breakout_map=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["breakout_port_group"]],
            ["state", "present", ["breakout_port_group"]],
        ],
    )

    breakout_port_group = module.params.get("breakout_port_group")
    description = module.params.get("description")
    breakout_map = module.params.get("breakout_map")
    state = module.params.get("state")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="infraBrkoutPortGrp",
            aci_rn="infra/funcprof/brkoutportgrp-{0}".format(breakout_port_group),
            module_object=breakout_port_group,
            target_filter={"name": breakout_port_group},
        ),
        child_classes=[],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="infraBrkoutPortGrp",
            class_config=dict(
                name=breakout_port_group,
                descr=description,
                brkoutMap=breakout_map,
            ),
        )

        aci.get_diff(aci_class="infraBrkoutPortGrp")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
