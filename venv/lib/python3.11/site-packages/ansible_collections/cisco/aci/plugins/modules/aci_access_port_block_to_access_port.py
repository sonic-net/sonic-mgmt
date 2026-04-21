#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Simon Metzger <smnmtzgr@gmail.com>
# Copyright: (c) 2020, Shreyas Srish <ssrish@cisco.com>
# Copyright: (c) 2020, Zak Lantz (@manofcolombia) <zakodewald@gmail.com>
# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_access_port_block_to_access_port
short_description: Manage Port blocks of Fabric Access Leaf/Spine Interface Port Selectors (infra:PortBlk)
description:
- Manage Port blocks of Fabric Access Interface Leaf/Spine Port Selectors on Cisco ACI fabrics.
options:
  interface_profile:
    description:
    - The name of the Fabric access policy leaf/spine interface profile.
    type: str
    aliases:
    - leaf_interface_profile_name
    - leaf_interface_profile
    - interface_profile_name
    - spine_interface_profile
    - spine_interface_profile_name
  access_port_selector:
    description:
    -  The name of the Fabric access policy leaf/spine interface port selector.
    type: str
    aliases: [ name, access_port_selector_name ]
  port_blk:
    description:
    - The name of the Fabric access policy interface port block.
    type: str
    aliases: [ leaf_port_blk_name, leaf_port_blk ]
  port_blk_description:
    description:
    - The description for the port block.
    type: str
    aliases: [ leaf_port_blk_description ]
  from_port:
    description:
    - The beginning (from-range) of the port range block for the port block.
    type: str
    aliases: [ from, fromPort, from_port_range ]
  to_port:
    description:
    - The end (to-range) of the port range block for the port block.
    type: str
    aliases: [ to, toPort, to_port_range ]
  from_card:
    description:
    - The beginning (from-range) of the card range block for the port block.
    type: str
    aliases: [ from_card_range ]
  to_card:
    description:
    - The end (to-range) of the card range block for the port block.
    type: str
    aliases: [ to_card_range ]
  type:
    description:
    - The type of port block to be created under respective access port.
    type: str
    choices: [ fex, leaf, spine ]
    default: leaf
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

notes:
-  If Adding a port block on an access leaf interface port selector of I(type) C(leaf),
  The I(interface_profile) and I(access_port_selector) must exist before using this module in your playbook.
  The M(cisco.aci.aci_interface_policy_leaf_profile) and M(cisco.aci.aci_access_port_to_interface_policy_leaf_profile) modules can be used for this.
-  If Adding a port block on an access interface port selector of C(type) C(spine),
  The I(interface_profile) and I(access_port_selector) must exist before using this module in your playbook.
  The M(cisco.aci.aci_access_spine_interface_profile) and M(cisco.aci.aci_access_spine_interface_selector) modules can be used for this.
seealso:
- module: cisco.aci.aci_interface_policy_leaf_profile
- module: cisco.aci.aci_access_port_to_interface_policy_leaf_profile
- module: cisco.aci.aci_access_spine_interface_profile
- module: cisco.aci.aci_access_spine_interface_selector
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:PortBlk).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Simon Metzger (@smnmtzgr)
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Associate a Fabric access policy interface port block (single port) to an interface selector
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_profile: leafintprfname
    access_port_selector: accessportselectorname
    port_blk: leafportblkname
    from_port: 13
    to_port: 13
    state: present
  delegate_to: localhost

- name: Associate a Fabric access policy interface port block (port range) to an interface selector
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_profile: leafintprfname
    access_port_selector: accessportselectorname
    port_blk: leafportblkname
    from_port: 13
    to_port: 16
    state: present
  delegate_to: localhost

- name: Associate a Fabric access policy interface port block (single port) to an interface selector of type fex
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    type: fex
    interface_profile: leafintprfname_fex
    access_port_selector: accessportselectorname_fex
    port_blk: leafportblkname_fex
    from_port: 13
    to_port: 13
    state: present
  delegate_to: localhost

- name: Associate a Fabric access policy interface port block (port range) to an interface selector of type fex
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    type: fex
    interface_profile: leafintprfname_fex
    access_port_selector: accessportselectorname_fex
    port_blk: leafportblkname_fex
    from_port: 13
    to_port: 16
    state: present
  delegate_to: localhost

- name: Query Specific Fabric access policy interface port block under given access port selector
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_profile: leafintprfname
    access_port_selector: accessportselectorname
    port_blk: leafportblkname
    state: query
  delegate_to: localhost
  register: query_result

- name: Query Specific Fabric access policy interface port block under given access port selector of type fex
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    type: fex
    interface_profile: leafintprfname_fex
    access_port_selector: accessportselectorname_fex
    port_blk: leafportblkname_fex
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Fabric access policy interface port blocks under given leaf interface profile
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_profile: leafintprfname
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Fabric access policy interface port blocks under given leaf interface profile of type fex
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    type: fex
    interface_profile: leafintprfname_fex
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Fabric access policy interface port blocks in the fabric
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Fabric access policy interface port blocks in the fabric of type fex
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    type: fex
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a Fabric access policy interface port block from an interface selector
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_profile: leafintprfname
    access_port_selector: accessportselectorname
    port_blk: leafportblkname
    from_port: 13
    to_port: 13
    state: absent
  delegate_to: localhost

- name: Remove a Fabric access policy interface port block from an interface selector of type fex
  cisco.aci.aci_access_port_block_to_access_port:
    host: apic
    username: admin
    password: SomeSecretPassword
    type: fex
    interface_profile: leafintprfname_fex
    access_port_selector: accessportselectorname_fex
    port_blk: leafportblkname_fex
    from_port: 13
    to_port: 13
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        interface_profile=dict(
            type="str",
            aliases=[
                "leaf_interface_profile_name",
                "leaf_interface_profile",
                "interface_profile_name",
                "spine_interface_profile",
                "spine_interface_profile_name",
            ],
        ),
        access_port_selector=dict(type="str", aliases=["name", "access_port_selector_name"]),  # Not required for querying all objects
        port_blk=dict(type="str", aliases=["leaf_port_blk_name", "leaf_port_blk"]),  # Not required for querying all objects
        port_blk_description=dict(type="str", aliases=["leaf_port_blk_description"]),
        from_port=dict(type="str", aliases=["from", "fromPort", "from_port_range"]),
        to_port=dict(type="str", aliases=["to", "toPort", "to_port_range"]),
        from_card=dict(type="str", aliases=["from_card_range"]),
        to_card=dict(type="str", aliases=["to_card_range"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        type=dict(type="str", default="leaf", choices=["fex", "leaf", "spine"]),  # This parameter is not required for querying all objects
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["interface_profile", "access_port_selector", "port_blk"]],
            ["state", "present", ["interface_profile", "access_port_selector", "port_blk", "from_port", "to_port"]],
        ],
    )

    interface_profile = module.params.get("interface_profile")
    access_port_selector = module.params.get("access_port_selector")
    port_blk = module.params.get("port_blk")
    port_blk_description = module.params.get("port_blk_description")
    from_port = module.params.get("from_port")
    to_port = module.params.get("to_port")
    from_card = module.params.get("from_card")
    to_card = module.params.get("to_card")
    state = module.params.get("state")
    type_port = module.params.get("type")

    aci = ACIModule(module)

    aci_class = "infraAccPortP"
    aci_rn = "accportprof"
    if type_port == "fex":
        aci_class = "infraFexP"
        aci_rn = "fexprof"
    subclass_1 = dict(
        aci_class=aci_class,
        aci_rn="{0}-{1}".format(aci_rn, interface_profile),
        module_object=interface_profile,
        target_filter={"name": interface_profile},
    )
    subclass_2 = dict(
        aci_class="infraHPortS",
        aci_rn="hports-{0}-typ-range".format(access_port_selector),
        module_object=access_port_selector,
        target_filter={"name": access_port_selector},
    )
    if type_port == "spine":
        subclass_1 = dict(
            aci_class="infraSpAccPortP",
            aci_rn="spaccportprof-{0}".format(interface_profile),
            module_object=interface_profile,
            target_filter={"name": interface_profile},
        )
        subclass_2 = dict(
            aci_class="infraSHPortS",
            aci_rn="shports-{0}-typ-range".format(access_port_selector),
            module_object=access_port_selector,
            target_filter={"name": access_port_selector},
        )
    aci.construct_url(
        root_class=dict(
            aci_class="infraInfra",
            aci_rn="infra",
            module_object="" if interface_profile or access_port_selector else None,
        ),
        subclass_1=subclass_1,
        subclass_2=subclass_2,
        subclass_3=dict(
            aci_class="infraPortBlk",
            aci_rn="portblk-{0}".format(port_blk),
            module_object=port_blk,
            target_filter={"name": port_blk},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="infraPortBlk",
            class_config=dict(
                descr=port_blk_description,
                name=port_blk,
                fromPort=from_port,
                toPort=to_port,
                fromCard=from_card,
                toCard=to_card,
            ),
        )

        aci.get_diff(aci_class="infraPortBlk")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
