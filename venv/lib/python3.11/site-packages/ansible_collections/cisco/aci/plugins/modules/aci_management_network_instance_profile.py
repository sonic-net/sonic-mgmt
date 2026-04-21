#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Tim Cragg (@timcragg) <tcragg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_management_network_instance_profile
version_added: "2.13.0"
short_description: Manage external management network instance profiles (mgmt:InstP).
description:
- Manage external management network instance profiles on Cisco ACI fabrics.
options:
  profile:
    description:
    - The name of the external management network instance profile.
    type: str
    aliases: [ name, profile_name ]
  qos_class:
    description:
    - QoS priority class identifier.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    aliases: [ qos, priority, prio ]
    choices: [ level1, level2, level3, level4, level5, level6, unspecified ]
  description:
    description:
    - The description for the external management network instance profile.
    type: str
    aliases: [ descr ]
  subnets:
    description:
    - The list of subnets in CIDR format to associate with the external management network instance profile.
    - When state is C(present) and a list of subnets is provided, any existing subnets will be removed from the object if they are not present in this list.
    - When subnets is set to an empty list and state is C(present), all existing subnets will be removed from the profile.
    type: list
    elements: str
    aliases: [ subnet_list, networks, network_list ]
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(mgmt:InstP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new external management network instance profile
  cisco.aci.aci_management_network_instance_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: lab_network_inst_profile
    subnets:
      - 10.20.30.0/24
      - 192.168.10.0/24
    state: present
  delegate_to: localhost

- name: Delete all subnets from management network instance profile
  cisco.aci.aci_management_network_instance_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: lab_network_inst_profile
    subnets: []
    state: present
  delegate_to: localhost

- name: Remove an external management network instance profile
  cisco.aci.aci_management_network_instance_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: lab_network_inst_profile
    state: absent
  delegate_to: localhost

- name: Query an external management network instance profile
  cisco.aci.aci_management_network_instance_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: lab_network_inst_profile
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all external management network instance profiles
  cisco.aci.aci_management_network_instance_profile:
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible_collections.cisco.aci.plugins.module_utils.constants import VALID_QOS_CLASSES


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        profile=dict(type="str", aliases=["name", "profile_name"]),
        qos_class=dict(type="str", aliases=["qos", "priority", "prio"], choices=VALID_QOS_CLASSES),
        description=dict(type="str", aliases=["descr"]),
        subnets=dict(type="list", elements="str", aliases=["subnet_list", "networks", "network_list"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["profile"]],
            ["state", "present", ["profile"]],
        ],
    )

    profile = module.params.get("profile")
    qos_class = module.params.get("qos_class")
    description = module.params.get("description")
    subnets = module.params.get("subnets")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="mgmtInstP",
            aci_rn="tn-mgmt/extmgmt-default/instp-{0}".format(profile),
            module_object=profile,
            target_filter={"name": profile},
        ),
        child_classes=["mgmtSubnet"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if subnets is not None:
            for subnet in subnets:
                child_configs.append(dict(mgmtSubnet=dict(attributes=dict(ip=subnet))))
            if isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("mgmtInstP", {}).get("children", []):
                    # Remove any existing subnet entries that are not in the requested subnet list
                    if child.get("mgmtSubnet") and child.get("mgmtSubnet").get("attributes", {}).get("ip") not in subnets:
                        child_configs.append(
                            {
                                "mgmtSubnet": {
                                    "attributes": {
                                        "ip": child.get("mgmtSubnet").get("attributes", {}).get("ip"),
                                        "status": "deleted",
                                    }
                                }
                            }
                        )

        aci.payload(
            aci_class="mgmtInstP",
            class_config=dict(
                descr=description,
                name=profile,
                nameAlias=name_alias,
                prio=qos_class,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="mgmtInstP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
