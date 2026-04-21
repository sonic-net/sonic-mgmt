#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_switch_block
short_description: Manage switch blocks (fabric:NodeBlk)
description:
- Manage fabric node blocks within switch associations (fabric:SpineS and
  fabric:LeafS) contained within fabric switch profiles (fabric:SpineP and fabric:LeafP)
options:
  name:
    description:
    - Name of the block
    type: str
    aliases: [ block_name ]
  switch_type:
    description:
    - Type of switch profile, leaf or spine
    type: str
    choices: [ leaf, spine ]
    required: true
  profile:
    description:
    - Name of an existing fabric spine or leaf switch profile
    type: str
    aliases: [ profile_name, switch_profile ]
  association:
    description:
    - Name of an existing switch association
    type: str
    aliases: [ association_name, switch_association ]
  description:
    description:
    - Description of the Node Block
    type: str
    aliases: [ descr ]
  from_node:
    description:
    - First Node ID of the block
    type: int
    aliases: [ from, from_ ]
  to_node:
    description:
    - Last Node ID of the block
    type: int
    aliases: [ to, to_ ]
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabricNodeBlk)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Create a spine switch association block
  cisco.aci.aci_fabric_switch_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_type: spine
    profile: my_spine_profile
    association: my_spine_switch_assoc
    name: my_spine_block
    from_node: 101
    to_node: 101
    state: present
  delegate_to: localhost

- name: Remove a spine switch profile association
  cisco.aci.aci_fabric_switch_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_type: spine
    profile: my_spine_profile
    association: my_spine_switch_assoc
    name: my_spine_block
    state: absent
  delegate_to: localhost

- name: Query a spine profile association
  cisco.aci.aci_fabric_switch_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_type: spine
    profile: my_spine_profile
    association: my_spine_switch_assoc
    name: my_spine_block
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["block_name"]),
        switch_type=dict(type="str", choices=["leaf", "spine"], required=True),
        profile=dict(type="str", aliases=["profile_name", "switch_profile"]),
        association=dict(type="str", aliases=["association_name", "switch_association"]),
        description=dict(type="str", aliases=["descr"]),
        from_node=dict(type="int", aliases=["from", "from_"]),
        to_node=dict(type="int", aliases=["to", "to_"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["profile", "association", "name"]],
            ["state", "present", ["profile", "association", "name"]],
        ],
    )

    aci = ACIModule(module)

    name = module.params.get("name")
    profile = module.params.get("profile")
    switch_type = module.params.get("switch_type")
    association = module.params.get("association")
    descr = module.params.get("descr")
    from_node = module.params.get("from_node")
    to_node = module.params.get("to_node")
    state = module.params.get("state")

    if switch_type == "spine":
        aci_root_class = "fabricSpineP"
        aci_root_rn = "fabric/spprof-{0}".format(profile)
        aci_subclass1_class = "fabricSpineS"
        aci_subclass1_rn = "spines-{0}-typ-range".format(association)
    elif switch_type == "leaf":
        aci_root_class = "fabricLeafP"
        aci_root_rn = "fabric/leprof-{0}".format(profile)
        aci_subclass1_class = "fabricLeafS"
        aci_subclass1_rn = "leaves-{0}-typ-range".format(association)

    aci.construct_url(
        root_class=dict(
            aci_class=aci_root_class,
            aci_rn=aci_root_rn,
            module_object=profile,
            target_filter={"name": profile},
        ),
        subclass_1=dict(
            aci_class=aci_subclass1_class,
            aci_rn=aci_subclass1_rn,
            module_object=association,
            target_filter={"name": association},
        ),
        subclass_2=dict(
            aci_class="fabricNodeBlk",
            aci_rn="nodeblk-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fabricNodeBlk",
            class_config=dict(name=name, descr=descr, from_=from_node, to_=to_node),
        )

        aci.get_diff(aci_class="fabricNodeBlk")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
