#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_leaf_switch_assoc
short_description: Manage leaf switch bindings to profiles and policy groups (fabric:LeafS and fabric:RsLeNodePGrp).
description:
- Manage fabric leaf switch associations (fabric:LeafS) to an existing fabric
  leaf profile (fabric:leafP) in an ACI fabric, and bind them to a
  policy group (fabric:RsLeNodePGrp)
options:
  profile:
    description:
    - Name of an existing fabric leaf switch profile
    type: str
    aliases: [ leaf_profile, leaf_switch_profile ]
  name:
    description:
    - Name of the switch association
    type: str
    aliases: [ association_name, switch_association ]
  policy_group:
    description:
    - Name of an existing leaf switch policy group
    type: str
  description:
    description:
    - Description of the Fabric Switch Association
    type: str
    aliases: [ descr ]
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
- The C(profile) must exist before using this module in your playbook.
  The M(cisco.aci.aci_fabric_leaf_profile) module can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(fabricLeafS) and B(fabricRsLeNodePGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Create a leaf switch profile association
  cisco.aci.aci_fabric_leaf_switch_assoc:
    host: apic
    username: admin
    password: SomeSecretPassword
    profile: my_leaf_profile
    name: my_leaf_switch_assoc
    policy_group: my_leaf_pol_grp
    state: present
  delegate_to: localhost
- name: Remove a leaf switch profile association
  cisco.aci.aci_fabric_leaf_switch_assoc:
    host: apic
    username: admin
    password: SomeSecretPassword
    profile: my_leaf_profile
    name: my_leaf_switch_assoc
    state: absent
  delegate_to: localhost
- name: Query a leaf profile association
  cisco.aci.aci_fabric_leaf_switch_assoc:
    host: apic
    username: admin
    password: SomeSecretPassword
    profile: my_leaf_profile
    name: my_leaf_switch_assoc
    state: query
  delegate_to: localhost
  register: query_result
- name: Query all leaf profiles
  cisco.aci.aci_fabric_leaf_switch_assoc:
    host: apic
    username: admin
    password: SomeSecretPassword
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        profile=dict(type="str", aliases=["leaf_profile", "leaf_switch_profile"]),
        name=dict(type="str", aliases=["association_name", "switch_association"]),
        policy_group=dict(type="str"),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["profile", "name"]],
            ["state", "present", ["profile", "name"]],
        ],
    )

    aci = ACIModule(module)

    profile = module.params.get("profile")
    name = module.params.get("name")
    policy_group = module.params.get("policy_group")
    description = module.params.get("description")
    state = module.params.get("state")
    child_classes = ["fabricRsLeNodePGrp", "fabricNodeBlk"]

    aci.construct_url(
        root_class=dict(
            aci_class="fabricLeafP",
            aci_rn="fabric/leprof-{0}".format(profile),
            module_object=profile,
            target_filter={"name": profile},
        ),
        subclass_1=dict(
            aci_class="fabricLeafS",
            aci_rn="leaves-{0}-typ-range".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if policy_group:
            tDn = "uni/fabric/funcprof/lenodepgrp-{0}".format(policy_group)
            child_configs.append(dict(fabricRsLeNodePGrp=dict(attributes=dict(tDn=tDn))))
        aci.payload(
            aci_class="fabricLeafS",
            class_config=dict(name=name, descr=description),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="fabricLeafS")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
