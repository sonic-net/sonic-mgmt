#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2024, Samita Bhattacharjee (@samitab) <samitab.cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_external_routing_profile
short_description: Manage Fabric External Routing Profiles (l3ext:FabricExtRoutingP)
description:
- Manage Fabric External Routing Profiles on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the Fabric External Routing Profile.
    type: str
    aliases: [ routing_profile, profile ]
  fabric_id:
    description:
    - The Fabric ID associated with the Fabric External Routing Profile.
    type: int
    aliases: [ fabric, fid]
  description:
    description:
    - The description of the Fabric External Routing Profile.
    type: str
    aliases: [ descr ]
  subnets:
    description:
    - The list of external subnet IP addresses.
    - Duplicate subnet IP addresses are not valid and would be ignored.
    type: list
    elements: str
    aliases: [ ip_addresses, ips ]
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
- This module requires an existing I(fabric_external_connection_profile).
  The module M(cisco.aci.aci_fabric_external_connection_profile) can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:FabricExtRoutingP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samitab)
"""

# TODO EXAMPLES
EXAMPLES = r"""
- name: Add an External Routing Profile
  cisco.aci.aci_fabric_external_routing_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    fabric_id: "1"
    description: "Fabric external routing profile"
    name: "ansible_fabric_ext_routing_profile"
    subnets:
      - 1.2.3.4/24
      - 5.6.7.8/24
    state: present
  delegate_to: localhost

- name: Query an External Routing Profile
  cisco.aci.aci_fabric_external_routing_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    fabric_id: 1
    name: ansible_fabric_ext_routing_profile
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all External Routing Profiles
  cisco.aci.aci_fabric_external_routing_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove an External Routing Profile
  cisco.aci.aci_fabric_external_routing_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    fabric_id: 1
    name: ansible_fabric_ext_routing_profile
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
        name=dict(type="str", aliases=["routing_profile", "profile"]),
        fabric_id=dict(type="int", aliases=["fabric", "fid"]),
        description=dict(type="str", aliases=["descr"]),
        subnets=dict(type="list", elements="str", aliases=["ip_addresses", "ips"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["fabric_id", "name"]],
            ["state", "present", ["fabric_id", "name"]],
        ],
    )

    aci = ACIModule(module)

    name = module.params.get("name")
    fabric_id = module.params.get("fabric_id")
    description = module.params.get("description")
    subnets = module.params.get("subnets")
    state = module.params.get("state")

    # Remove duplicate subnets
    if isinstance(subnets, list):
        subnets = list(dict.fromkeys(subnets))

    aci.construct_url(
        root_class=dict(
            aci_class="fvFabricExtConnP",
            aci_rn="tn-infra/fabricExtConnP-{0}".format(fabric_id),
            module_object=fabric_id,
            target_filter={"id": fabric_id},
        ),
        subclass_1=dict(
            aci_class="l3extFabricExtRoutingP",
            aci_rn="fabricExtRoutingP-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=["l3extSubnet"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []

        # Validate if existing and remove subnet objects when the config does not match the provided config.
        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            subnets = [] if subnets is None else subnets
            for child in aci.existing[0].get("l3extFabricExtRoutingP", {}).get("children", {}):
                if child.get("l3extSubnet") and child.get("l3extSubnet").get("attributes").get("ip") not in subnets:
                    child_configs.append(
                        {
                            "l3extSubnet": {
                                "attributes": {
                                    "ip": child.get("l3extSubnet").get("attributes").get("ip"),
                                    "status": "deleted",
                                }
                            }
                        }
                    )

        if subnets is not None:
            for subnet in subnets:
                child_configs.append({"l3extSubnet": {"attributes": {"ip": subnet}}})

        aci.payload(
            aci_class="l3extFabricExtRoutingP",
            class_config=dict(
                name=name,
                descr=description,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="l3extFabricExtRoutingP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
