#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Samita Bhattacharjee (@samitab) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_pod_remote_pool
short_description: Manage Fabric Pod Remote Pool (fabric:ExtSetupP)
description:
- Manage Remote Pools on Fabric Pod Subnets.
options:
  pod_id:
    description:
    - The Pod ID for the Remote Pool.
    type: int
    aliases: [ pod ]
  description:
    description:
    - The description for the Remote Pool.
    type: str
    aliases: [desc]
  remote_id:
    description:
    - The Identifier for the Remote Pool.
    type: int
    aliases: [ id ]
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
  remote_pool:
    description:
    - The subnet IP address pool for the Remote Pool.
    - Must be valid IPv4 and include the subnet mask.
    - Example 192.168.1.0/24
    type: str
    aliases: [ pool ]
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
- The C(Fabric Pod Setup Policy) must exist before using this module in your playbook.
  The M(cisco.aci.aci_fabric_pod) module can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabric:ExtSetupP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Add a Remote Pool to a fabric pod setup policy
  cisco.aci.aci_fabric_pod_remote_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 2
    remote_id: 1
    remote_pool: 10.6.2.0/24
    state: present
  delegate_to: localhost

- name: Query the Remote Pool on a fabric pod setup policy
  cisco.aci.aci_fabric_pod_remote_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 2
    remote_id: 1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query Remote Pools on all fabric pod setup policies
  cisco.aci.aci_fabric_pod_remote_pool:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a Remote Pool from a fabric pod setup policy
  cisco.aci.aci_fabric_pod_external_tep:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 2
    remote_id: 1
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
        pod_id=dict(type="int", aliases=["pod"]),
        description=dict(type="str", aliases=["desc"]),
        remote_id=dict(type="int", aliases=["id"]),
        name_alias=dict(type="str"),
        remote_pool=dict(type="str", aliases=["pool"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["pod_id", "remote_id"]],
            ["state", "present", ["pod_id", "remote_id"]],
        ],
    )

    aci = ACIModule(module)

    pod_id = module.params.get("pod_id")
    description = module.params.get("description")
    remote_id = module.params.get("remote_id")
    name_alias = module.params.get("name_alias")
    remote_pool = module.params.get("remote_pool")
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
        subclass_1=dict(
            aci_class="fabricExtSetupP",
            aci_rn="extsetupp-{0}".format(remote_id),
            module_object=remote_id,
            target_filter={"extPoolId": remote_id},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fabricExtSetupP",
            class_config=dict(
                descr=description,
                extPoolId=remote_id,
                nameAlias=name_alias,
                tepPool=remote_pool,
            ),
        )

        aci.get_diff(aci_class="fabricExtSetupP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
