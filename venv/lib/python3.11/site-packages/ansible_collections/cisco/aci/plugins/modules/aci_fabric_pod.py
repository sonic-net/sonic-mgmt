#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Samita Bhattacharjee (@samitab) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_pod
short_description: Manage Fabric Pod Setup Policy (fabric:SetupP)
description:
- Manage Fabric Pod Setup Policy on Cisco ACI fabrics.
options:
  pod_id:
    description:
    - The Pod ID for the Fabric Pod Setup Policy.
    - Accepted value range between C(1) and C(254).
    type: int
    aliases: [ pod, id ]
  pod_type:
    description:
    - The type of the Pod. Use C(physical) or C(virtual).
    - The APIC defaults to C(physical) when unset during creation.
    type: str
    choices: [ physical, virtual ]
    aliases: [ type ]
  tep_pool:
    description:
    - The TEP address pool for the Fabric Pod Setup Policy.
    - Must be valid IPv4 and include the subnet mask.
    - Example 192.168.1.0/24
    type: str
    aliases: [ tep, pool ]
  description:
    description:
    - The description for the Fabric Pod Setup Policy.
    type: str
    aliases: [ descr ]
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
  description: More information about the internal APIC class B(fabric:SetupP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Add a fabric pod setup policy
  cisco.aci.aci_fabric_pod:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 1
    tep_pool: 10.0.0.0/16
    state: present
  delegate_to: localhost

- name: Query the fabric pod setup policy
  cisco.aci.aci_fabric_pod:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all fabric pod setup policies
  cisco.aci.aci_fabric_pod:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a fabric pod setup policy
  cisco.aci.aci_fabric_pod:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 1
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
    aci_owner_spec,
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
        pod_id=dict(type="int", aliases=["pod", "id"]),
        pod_type=dict(type="str", choices=["physical", "virtual"], aliases=["type"]),
        tep_pool=dict(type="str", aliases=["tep", "pool"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["pod_id"]],
            ["state", "present", ["pod_id"]],
        ],
    )

    aci = ACIModule(module)

    name_alias = module.params.get("name_alias")
    pod_id = module.params.get("pod_id")
    pod_type = module.params.get("pod_type")
    tep_pool = module.params.get("tep_pool")
    description = module.params.get("description")
    state = module.params.get("state")

    if pod_id is not None and int(pod_id) not in range(1, 254):
        aci.fail_json(msg="Pod ID: {0} is invalid; it must be in the range of 1 to 254.".format(pod_id))

    aci.construct_url(
        root_class=dict(
            aci_class="fabricSetupP",
            aci_rn="controller/setuppol/setupp-{0}".format(pod_id),
            module_object=pod_id,
            target_filter={"podId": pod_id},
        ),
        child_classes=["fabricExtRoutablePodSubnet", "fabricExtSetupP"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fabricSetupP",
            class_config=dict(
                podId=pod_id,
                podType=pod_type,
                tepPool=tep_pool,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="fabricSetupP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
