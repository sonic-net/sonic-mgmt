#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Sabari Jaganathan <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_interface_policy_group
short_description: Manage Fabric Interface Policy Groups (fabric:LePortPGrp and fabric:SpPortPGrp)
description:
- Manage Fabric Interface Policy Groups on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the Fabric Leaf or Spine Interface Policy Group.
    type: str
    aliases: [ policy_group ]
  description:
    description:
    - The description of the Fabric Leaf or Spine Interface Policy Group.
    type: str
    aliases: [ descr ]
  type:
    description:
    - The type of the Fabric Leaf or Spine Interface Policy Group.
    - Use C(leaf) to create a Fabric Leaf Interface Policy Group.
    - Use C(spine) to create a Fabric Spine Interface Policy Group.
    type: str
    aliases: [ policy_group_type ]
    choices: [ leaf, spine ]
    required: true
  dwdm_policy:
    description:
    - The name of the DWDM policy to bind to the Fabric Leaf or Spine Interface Policy Group.
    type: str
  link_level_policy:
    description:
    - The name of the Link Level policy to bind to the Fabric Leaf or Spine Interface Policy Group.
    type: str
  link_flap_policy:
    description:
    - The name of the Link Flap policy to bind to the Fabric Leaf or Spine Interface Policy Group.
    type: str
  l3_interface_policy:
    description:
    - The name of the L3 Interface policy to bind to the Fabric Leaf or Spine Interface Policy Group.
    type: str
  macsec_policy:
    description:
    - The name of the MACSec policy to bind to the Fabric Leaf or Spine Interface Policy Group.
    type: str
  monitoring_policy:
    description:
    - The name of the Monitoring policy to bind to the Fabric Leaf or Spine Interface Policy Group.
    type: str
  transceiver_policy_tdn:
    description:
    - The target Dn of the Transceiver policy to bind to the Fabric Leaf or Spine Interface Policy Group.
    - The Transceiver policy group is only compatible with ACI versions 6.0(2h) and higher.
    type: str
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
  description: More information about the internal APIC class B(fabric:LePortPGrp, fabric:SpPortPGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sabari Jaganathan (@sajagana)
"""

EXAMPLES = r"""
- name: Add a Fabric Leaf Policy Group
  cisco.aci.aci_fabric_interface_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: leaf_policy_group
    type: leaf
    state: present
  delegate_to: localhost

- name: Query a Fabric Leaf Policy Group with name
  cisco.aci.aci_fabric_interface_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: leaf_policy_group
    type: leaf
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Fabric Leaf Policy Groups
  cisco.aci.aci_fabric_interface_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    type: leaf
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a Fabric Leaf Policy Group
  cisco.aci.aci_fabric_interface_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: leaf_policy_group
    type: leaf
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
        description=dict(type="str", aliases=["descr"]),
        name_alias=dict(type="str"),
        type=dict(type="str", aliases=["policy_group_type"], choices=["leaf", "spine"], required=True),
        dwdm_policy=dict(type="str"),
        link_level_policy=dict(type="str"),
        link_flap_policy=dict(type="str"),
        l3_interface_policy=dict(type="str"),
        macsec_policy=dict(type="str"),
        monitoring_policy=dict(type="str"),
        transceiver_policy_tdn=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
    )

    aci = ACIModule(module)

    name = module.params.get("name")
    description = module.params.get("description")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")
    policy_group_type = module.params.get("type")
    dwdm_policy = module.params.get("dwdm_policy")
    link_level_policy = module.params.get("link_level_policy")
    link_flap_policy = module.params.get("link_flap_policy")
    l3_interface_policy = module.params.get("l3_interface_policy")
    macsec_policy = module.params.get("macsec_policy")
    monitoring_policy = module.params.get("monitoring_policy")
    transceiver_policy_tdn = module.params.get("transceiver_policy_tdn")

    if policy_group_type == "leaf":
        policy_group_class_name = "fabricLePortPGrp"
        policy_group_class_rn = "leportgrp-{0}".format(name)
    else:
        policy_group_class_name = "fabricSpPortPGrp"
        policy_group_class_rn = "spportgrp-{0}".format(name)

    child_classes = [
        "fabricRsDwdmFabIfPol",
        "fabricRsFIfPol",
        "fabricRsFLinkFlapPol",
        "fabricRsL3IfPol",
        "fabricRsMacsecFabIfPol",
        "fabricRsMonIfFabricPol",
    ]

    if transceiver_policy_tdn is not None:
        child_classes.append("fabricRsOpticsFabIfPol")

    aci.construct_url(
        root_class=dict(
            aci_class="fabric",
            aci_rn="fabric",
        ),
        subclass_1=dict(
            aci_class="fabricFuncP",
            aci_rn="funcprof",
        ),
        subclass_2=dict(
            aci_class=policy_group_class_name,
            aci_rn=policy_group_class_rn,
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if dwdm_policy is not None:
            child_configs.append(dict(fabricRsDwdmFabIfPol=dict(attributes=dict(tnDwdmFabIfPolName=dwdm_policy))))
        if link_level_policy is not None:
            child_configs.append(dict(fabricRsFIfPol=dict(attributes=dict(tnFabricFIfPolName=link_level_policy))))
        if link_flap_policy is not None:
            child_configs.append(dict(fabricRsFLinkFlapPol=dict(attributes=dict(tnFabricFLinkFlapPolName=link_flap_policy))))
        if l3_interface_policy is not None:
            child_configs.append(dict(fabricRsL3IfPol=dict(attributes=dict(tnL3IfPolName=l3_interface_policy))))
        if macsec_policy is not None:
            child_configs.append(dict(fabricRsMacsecFabIfPol=dict(attributes=dict(tnMacsecFabIfPolName=macsec_policy))))
        if monitoring_policy is not None:
            child_configs.append(dict(fabricRsMonIfFabricPol=dict(attributes=dict(tnMonFabricPolName=monitoring_policy))))
        if transceiver_policy_tdn is not None:
            child_configs.append(dict(fabricRsOpticsFabIfPol=dict(attributes=dict(tDn=transceiver_policy_tdn))))

        aci.payload(
            aci_class=policy_group_class_name,
            class_config=dict(
                name=name,
                descr=description,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class=policy_group_class_name)

        aci.post_config()

    if state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
