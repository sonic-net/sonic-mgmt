#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Anvitha Jain <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_leaf_fc_policy_group
short_description: Manage Fibre Channel (FC) interface policy groups (infra:FcAccBndlGrp and infra:FcAccPortGrp)
description:
- Manage Fibre Channel (FC) interface policy groups on Cisco ACI fabrics.
options:
  policy_group:
    description:
    - The name of the Fibre Channel (FC) interface policy groups.
    type: str
    aliases: [ name, policy_group_name ]
  description:
    description:
    - The description of the Fibre Channel (FC) interface policy group.
    type: str
    aliases: [ descr ]
  lag_type:
    description:
    - Selector for the type of Fibre Channel (FC) interface policy group.
    - C(port) for Fiber Channel (FC)
    - C(port_channel) for Fiber Channel Port Channel (FC PC)
    type: str
    required: true
    choices: [ port, port_channel ]
    aliases: [ lag_type_name ]
  fibre_channel_interface_policy:
    description:
    - The name of the fibre channel interface policy used by the Fibre Channel (FC) interface policy group.
    type: str
    aliases: [ fibre_channel_interface_policy_name ]
  port_channel_policy:
    description:
    - The name of the port channel policy used by the Fibre Channel (FC) interface policy group.
    type: str
    aliases: [ port_channel_policy_name ]
  attached_entity_profile:
    description:
    - The name of the attached entity profile (AEP) used by the Fibre Channel (FC) interface policy group.
    type: str
    aliases: [ aep_name, aep ]
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
- When using the module please select the appropriate link_aggregation_type (lag_type).
- C(port) for Fiber Channel(FC), C(port_channel) for Fiber Channel Port Channel(VPC).
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:FcAccPortGrp) and B(infra:FcAccBndlGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Anvitha Jain (@anvjain)
"""

EXAMPLES = r"""
- name: Create a Fiber Channel (FC) Interface Policy Group
  cisco.aci.aci_interface_policy_leaf_fc_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: port
    fibre_channel_interface_policy: fcinterfacepolicy
    description: policygroupname description
    attached_entity_profile: aep
    state: present
  delegate_to: localhost

- name: Create a Fiber Channel Port Channel (FC PC) Interface Policy Group
  cisco.aci.aci_interface_policy_leaf_fc_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: port_channel
    fibre_channel_interface_policy: fcinterfacepolicy
    description: policygroupname description
    attached_entity_profile: aep
    port_channel_policy: lacppolicy
    state: present
  delegate_to: localhost

- name: Query all Leaf Access Port Policy Groups of type link
  cisco.aci.aci_interface_policy_leaf_fc_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: port_channel
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific Lead Access Port Policy Group
  cisco.aci.aci_interface_policy_leaf_fc_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: port
    policy_group: policygroupname
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete an Interface policy Leaf Policy Group
  cisco.aci.aci_interface_policy_leaf_fc_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: port
    policy_group: policygroupname
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
        # NOTE: Since this module needs to include both infra:FcAccPortGrp (for FC) and infra:FcAccBndlGrp (for FC PC):
        # NOTE: The user(s) can make a choice between (port(FC), port_channel(FC PC))
        lag_type=dict(type="str", required=True, aliases=["lag_type_name"], choices=["port", "port_channel"]),
        policy_group=dict(type="str", aliases=["name", "policy_group_name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        fibre_channel_interface_policy=dict(type="str", aliases=["fibre_channel_interface_policy_name"]),
        port_channel_policy=dict(type="str", aliases=["port_channel_policy_name"]),
        attached_entity_profile=dict(type="str", aliases=["aep_name", "aep"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["policy_group"]],
            ["state", "present", ["policy_group"]],
        ],
    )

    policy_group = module.params.get("policy_group")
    description = module.params.get("description")
    lag_type = module.params.get("lag_type")
    fibre_channel_interface_policy = module.params.get("fibre_channel_interface_policy")
    port_channel_policy = module.params.get("port_channel_policy")
    attached_entity_profile = module.params.get("attached_entity_profile")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)

    if lag_type == "port":
        aci_class_name = "infraFcAccPortGrp"
        dn_name = "fcaccportgrp"
    elif lag_type == "port_channel":
        aci_class_name = "infraFcAccBndlGrp"
        dn_name = "fcaccbundle"

    class_config_dict = dict(
        name=policy_group,
        descr=description,
        nameAlias=name_alias,
    )

    child_configs = []
    if fibre_channel_interface_policy is not None:
        child_configs.append(
            dict(
                infraRsFcL2IfPol=dict(
                    attributes=dict(
                        tnFcIfPolName=fibre_channel_interface_policy,
                    ),
                ),
            )
        )
    if attached_entity_profile is not None:
        child_configs.append(
            dict(
                infraRsFcAttEntP=dict(
                    attributes=dict(
                        tDn="uni/infra/attentp-{0}".format(attached_entity_profile),
                    ),
                ),
            )
        )

    # Add infraRsFcLagPol binding only when port_channel_policy is defined
    if lag_type == "port_channel" and port_channel_policy is not None:
        child_configs.append(
            dict(
                infraRsFcLagPol=dict(
                    attributes=dict(
                        tnLacpLagPolName=port_channel_policy,
                    ),
                ),
            )
        )

    aci.construct_url(
        root_class=dict(
            aci_class=aci_class_name,
            aci_rn="infra/funcprof/{0}-{1}".format(dn_name, policy_group),
            module_object=policy_group,
            target_filter={"name": policy_group},
        ),
        child_classes=[
            "infraRsFcL2IfPol",
            "infraRsFcLagPol",
            "infraRsFcAttEntP",
        ],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=aci_class_name,
            class_config=class_config_dict,
            child_configs=child_configs,
        )

        aci.get_diff(aci_class=aci_class_name)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
