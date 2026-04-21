#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Sabari Jaganathan <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_leaf_profile_fex_policy_group
short_description: Manage leaf interface profiles fex policy group (infra:FexBndlGrp)
description:
- Manage leaf interface profiles fex policy group on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the Fex Profile Policy Group.
    type: str
    aliases: [ policy_group ]
  fex_profile:
    description:
    - The name of the Fex Profile.
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
  description: More information about the internal APIC class B(infra:FexBndlGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sabari Jaganathan (@sajagana)
"""

EXAMPLES = r"""
- name: Add a new fex policy group
  cisco.aci.aci_interface_policy_leaf_profile_fex_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: fex_policy_group
    fex_profile: anstest_fex_profile
    state: present
  delegate_to: localhost

- name: Add list of fex policy groups
  cisco.aci.aci_interface_policy_leaf_profile_fex_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: "{{ item.name }}"
    fex_profile: "{{ item.fex_profile }}"
    state: present
  delegate_to: localhost
  with_items:
    - name: fex_policy_group_1
      fex_profile: anstest_fex_profile
    - name: fex_policy_group_2
      fex_profile: anstest_fex_profile

- name: Query a fex policy group under fex profile
  cisco.aci.aci_interface_policy_leaf_profile_fex_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: fex_policy_group
    fex_profile: anstest_fex_profile
    state: query
  delegate_to: localhost

- name: Query all fex policy groups under fex profile
  cisco.aci.aci_interface_policy_leaf_profile_fex_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    fex_profile: anstest_fex_profile
    state: query
  delegate_to: localhost

- name: Query all fex policy groups with name
  cisco.aci.aci_interface_policy_leaf_profile_fex_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: fex_policy_group
    state: query
  delegate_to: localhost

- name: Query all fex policy groups
  cisco.aci.aci_interface_policy_leaf_profile_fex_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove fex policy group
  cisco.aci.aci_interface_policy_leaf_profile_fex_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: fex_policy_group
    fex_profile: anstest_fex_profile
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
        name=dict(type="str", aliases=["policy_group"]),
        fex_profile=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "fex_profile"]],
            ["state", "present", ["name", "fex_profile"]],
        ],
    )

    name = module.params.get("name")
    fex_profile = module.params.get("fex_profile")
    state = module.params.get("state")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="infraFexP",
            aci_rn="infra/fexprof-{0}".format(fex_profile),
            module_object=fex_profile,
            target_filter={"name": fex_profile},
        ),
        subclass_1=dict(
            aci_class="infraFexBndlGrp",
            aci_rn="fexbundle-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="infraFexBndlGrp",
            class_config=dict(
                name=name,
            ),
        )

        aci.get_diff(aci_class="infraFexBndlGrp")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
