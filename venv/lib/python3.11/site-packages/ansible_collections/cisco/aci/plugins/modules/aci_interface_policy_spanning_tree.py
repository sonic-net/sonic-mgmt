#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Eric Girard <@netgirard>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_spanning_tree
short_description: Manage spanning tree interface policies (stp:IfPol)
description:
- Manage spanning tree interface policies on Cisco ACI fabrics.
options:
  stp_policy:
    description:
    - The name of the STP policy.
    type: str
    aliases: [ name ]
  description:
    description:
    - The description for the policy.
    type: str
    aliases: [ descr ]
  bpdu_guard:
    description:
    - The BPDU-Guard state.
    type: bool
    default: false
  bpdu_filter:
    description:
    - The BPDU-Filter state.
    type: bool
    default: false
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(stp:IfPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Eric Girard (@netgirard)
"""

EXAMPLES = r"""
- name: Add a spanning interface policy
  cisco.aci.aci_interface_policy_spanning_tree:
    host: '{{ inventory_hostname }}'
    username: '{{ username }}'
    password: '{{ password }}'
    stp_policy: 'my_policy'
    description: 'my_description'
    bpdu_guard: true
    bpdu_filter: false
    state: present
  delegate_to: localhost

- name: Query a specific spanning interface policy
  cisco.aci.aci_interface_policy_spanning_tree:
    host: '{{ inventory_hostname }}'
    username: '{{ username }}'
    password: '{{ password }}'
    stp_policy: 'my_policy'
    state: query
  delegate_to: localhost

- name: Query all spanning interface policies
  cisco.aci.aci_interface_policy_spanning_tree:
    host: '{{ inventory_hostname }}'
    username: '{{ username }}'
    password: '{{ password }}'
    state: query
  delegate_to: localhost

- name: Remove a specific spanning interface policy
  cisco.aci.aci_interface_policy_spanning_tree:
    host: '{{ inventory_hostname }}'
    username: '{{ username }}'
    password: '{{ password }}'
    stp_policy: 'my_policy'
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
        stp_policy=dict(type="str", aliases=["name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        bpdu_guard=dict(type="bool", default=False),
        bpdu_filter=dict(type="bool", default=False),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["stp_policy"]],
            ["state", "present", ["stp_policy"]],
        ],
    )

    stp_policy = module.params.get("stp_policy")
    description = module.params.get("description")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    # Build ctrl value for request
    ctrl = []
    if module.params.get("bpdu_filter") is True:
        ctrl.append("bpdu-filter")
    if module.params.get("bpdu_guard") is True:
        ctrl.append("bpdu-guard")

    # Order of control string must match ACI return value for idempotency
    ctrl = ",".join(sorted(ctrl)) if ctrl else None

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="stpIfPol",
            aci_rn="infra/ifPol-{0}".format(stp_policy),
            module_object=stp_policy,
            target_filter={"name": stp_policy},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="stpIfPol",
            class_config=dict(
                name=stp_policy,
                ctrl=ctrl,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="stpIfPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
