#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
module: aci_maintenance_group
short_description: This creates an ACI maintenance group (maint:MaintGrp)
description:
    - This modules creates an ACI maintenance group.
options:
    group:
        description:
        - The name of the maintenance group.
        type: str
    policy:
        description:
        - The name of the maintenance policy.
        type: str
        aliases: [ maintenancepol ]
    firmware_nodes_type:
        description:
        - The firmware type of nodes in the maintenance group.
        - The APIC defaults to C(switch) when unset during creation.
        type: str
        choices: [ c_apic_patch, catalog, config, controller, controller_patch, plugin, plugin_package, switch, switch_patch, vpod ]
    type_group:
        description:
        - The type of the maintenance group.
        - The APIC defaults to C(range) when unset during creation.
        type: str
        choices: [ all, all_in_pod, range ]
    description:
        description:
        - Description of the maintenance group.
        type: str
        aliases: [ descr ]
    state:
        description:
        - Use C(present) or C(absent) for adding or removing.
        - Use C(query) for listing an object or multiple objects.
        type: str
        choices: [absent, present, query]
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
- The C(policy) used must exist before using this module in your playbook.
- The M(cisco.aci.aci_maintenance_policy) module can be used for this.
seealso:
- module: cisco.aci.aci_maintenance_policy
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(maint:MaintGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
    - Steven Gerhart (@sgerhart)
    - Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Create a maintenance group
  cisco.aci.aci_maintenance_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    group: my_maintenance_group
    policy: my_maintenance_policy
    state: present
  delegate_to: localhost

- name: Delete a maintenance group
  cisco.aci.aci_maintenance_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    group: my_maintenance_group
    state: absent
  delegate_to: localhost

- name: Query all maintenance groups
  cisco.aci.aci_maintenance_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific maintenance group
  cisco.aci.aci_maintenance_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    group: my_maintenance_group
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import MATCH_TYPE_GROUP_MAPPING, MATCH_FIRMWARE_NODES_TYPE_MAPPING
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        group=dict(type="str"),  # Not required for querying all objects
        policy=dict(type="str", aliases=["maintenancepol"]),  # Not required for querying all objects
        firmware_nodes_type=dict(type="str", choices=list(MATCH_FIRMWARE_NODES_TYPE_MAPPING.keys())),
        type_group=dict(type="str", choices=list(MATCH_TYPE_GROUP_MAPPING.keys())),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["group"]],
            ["state", "present", ["group"]],
        ],
    )

    state = module.params.get("state")
    group = module.params.get("group")
    policy = module.params.get("policy")
    firmware_nodes_type = MATCH_FIRMWARE_NODES_TYPE_MAPPING.get(module.params.get("firmware_nodes_type"))
    type_group = MATCH_TYPE_GROUP_MAPPING.get(module.params.get("type_group"))
    description = module.params.get("description")
    name_alias = module.params.get("name_alias")
    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="maintMaintGrp",
            aci_rn="fabric/maintgrp-{0}".format(group),
            target_filter={"name": group},
            module_object=group,
        ),
        child_classes=["maintRsMgrpp"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="maintMaintGrp",
            class_config=dict(
                name=group,
                fwtype=firmware_nodes_type,
                type=type_group,
                descr=description,
                nameAlias=name_alias,
            ),
            child_configs=[
                dict(
                    maintRsMgrpp=dict(
                        attributes=dict(
                            tnMaintMaintPName=policy,
                        ),
                    ),
                ),
            ],
        )

        aci.get_diff(aci_class="maintMaintGrp")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
