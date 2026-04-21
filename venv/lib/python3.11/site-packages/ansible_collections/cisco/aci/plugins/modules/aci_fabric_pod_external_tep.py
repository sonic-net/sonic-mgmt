#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Samita Bhattacharjee (@samitab) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_pod_external_tep
short_description: Manage Fabric Pod External TEP (fabric:ExtRoutablePodSubnet)
description:
- Manage Fabric Pod External TEP Subnets.
options:
  pod_id:
    description:
    - The Pod ID for the External TEP.
    type: int
    aliases: [ pod ]
  description:
    description:
    - The description for the External TEP.
    type: str
    aliases: [ descr ]
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
  external_tep_pool:
    description:
    - The subnet IP address pool for the External TEP.
    - Must be valid IPv4 and include the subnet mask.
    - Example 192.168.1.0/24
    type: str
    aliases: [ ip, ip_address, tep_pool, pool ]
  reserve_address_count:
    description:
    - Indicates the number of IP addresses that are reserved from the start of the subnet.
    type: int
    aliases: [ address_count ]
  status:
    description:
    - State of the External TEP C(active) or C(inactive).
    - An External TEP can only be deleted when the state is inactive.
    - The APIC defaults to C(active) when unset during creation.
    type: str
    choices: [ active, inactive ]
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
  description: More information about the internal APIC class B(fabric:ExtRoutablePodSubnet).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Add an External TEP to a fabric pod setup policy
  cisco.aci.aci_fabric_pod_external_tep:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 2
    external_tep_pool: 10.6.1.0/24
    reserve_address_count: 5
    status: active
    state: present
  delegate_to: localhost

- name: Change an External TEP state on a fabric pod setup policy to inactive
  cisco.aci.aci_fabric_pod_external_tep:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 2
    external_tep_pool: 10.6.1.0/24
    status: inactive
    state: present
  delegate_to: localhost

- name: Query the External TEP on a fabric pod setup policy
  cisco.aci.aci_fabric_pod_external_tep:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 2
    external_tep_pool: 10.6.1.0/24
    state: query
  delegate_to: localhost
  register: query_result

- name: Query External TEPs on all fabric pod setup policies
  cisco.aci.aci_fabric_pod_external_tep:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete an External TEP on a fabric pod setup policy
  cisco.aci.aci_fabric_pod_external_tep:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 2
    external_tep_pool: 10.6.1.0/24
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
        name_alias=dict(type="str"),
        pod_id=dict(type="int", aliases=["pod"]),
        external_tep_pool=dict(type="str", aliases=["ip", "ip_address", "tep_pool", "pool"]),
        reserve_address_count=dict(type="int", aliases=["address_count"]),
        status=dict(type="str", choices=["active", "inactive"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["pod_id", "external_tep_pool"]],
            ["state", "present", ["pod_id", "external_tep_pool"]],
        ],
    )

    aci = ACIModule(module)

    pod_id = module.params.get("pod_id")
    descr = module.params.get("descr")
    name_alias = module.params.get("name_alias")
    external_tep_pool = module.params.get("external_tep_pool")
    reserve_address_count = module.params.get("reserve_address_count")
    status = module.params.get("status")
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
            aci_class="fabricExtRoutablePodSubnet",
            aci_rn="extrtpodsubnet-[{0}]".format(external_tep_pool),
            module_object=external_tep_pool,
            target_filter={"pool": external_tep_pool},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fabricExtRoutablePodSubnet",
            class_config=dict(
                descr=descr,
                nameAlias=name_alias,
                pool=external_tep_pool,
                reserveAddressCount=reserve_address_count,
                state=status,
            ),
        )

        aci.get_diff(aci_class="fabricExtRoutablePodSubnet")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
