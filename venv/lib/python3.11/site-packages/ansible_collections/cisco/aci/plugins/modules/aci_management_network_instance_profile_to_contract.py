#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Tim Cragg (@timcragg) <tcragg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_management_network_instance_profile_to_contract
version_added: "2.13.0"
short_description: Bind Consumed Contract to External Management Network Instance Profiles (mgmt:RsOoBCons)
description:
- Bind Consumed Contract to External Management Network Instance Profiles on Cisco ACI fabrics.
options:
  profile:
    description:
    - The name of the External Management Network Instance Profile.
    type: str
    aliases: [ profile_name ]
  consumed_contract:
    description:
    - The name of the consumed contract.
    type: str
    aliases: [ contract_name, name ]
  dscp_priority:
    description:
    - The QoS priority class identifier.
    - This defaults to "unspecified" when unset on the APIC during object creation.
    type: str
    choices: [ level1, level2, level3, level4, level5, level6, unspecified ]
    aliases: [ priority, qos ]
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
  description: More information about the internal APIC class B(mgmt:RsOoBCons).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a Consumed Contract
  cisco.aci.aci_management_network_instance_profile_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    profile: ansible_instance_profile
    consumed_contract: ansible_contract
    dscp_priority: level2
    state: present
  delegate_to: localhost

- name: Query all Consumed Contracts
  cisco.aci.aci_management_network_instance_profile_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific Consumed Contract
  cisco.aci.aci_management_network_instance_profile_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    instance_profile: ansible_instance_profile
    consumed_contract: ansible_contract
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a Consumed Contract
  cisco.aci.aci_management_network_instance_profile_to_contract:
    host: apic
    username: admin
    password: SomeSecretPassword
    profile: ansible_instance_profile
    consumed_contract: ansible_contract
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import VALID_QOS_CLASSES


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        profile=dict(type="str", aliases=["profile_name"]),
        consumed_contract=dict(type="str", aliases=["contract_name", "name"]),
        dscp_priority=dict(type="str", choices=VALID_QOS_CLASSES, aliases=["priority", "qos"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["profile", "consumed_contract"]],
            ["state", "present", ["profile", "consumed_contract"]],
        ],
    )

    profile = module.params.get("profile")
    consumed_contract = module.params.get("consumed_contract")
    dscp_priority = module.params.get("dscp_priority")
    state = module.params.get("state")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="mgmtInstP",
            aci_rn="tn-mgmt/extmgmt-default/instp-{0}".format(profile),
            module_object=profile,
            target_filter={"name": profile},
        ),
        subclass_1=dict(
            aci_class="mgmtRsOoBCons",
            aci_rn="rsooBCons-{0}".format(consumed_contract),
            module_object=consumed_contract,
            target_filter={"tnVzOOBBrCPName": consumed_contract},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="mgmtRsOoBCons",
            class_config=dict(
                tnVzOOBBrCPName=consumed_contract,
                prio=dscp_priority,
            ),
        )

        aci.get_diff(aci_class="mgmtRsOoBCons")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
