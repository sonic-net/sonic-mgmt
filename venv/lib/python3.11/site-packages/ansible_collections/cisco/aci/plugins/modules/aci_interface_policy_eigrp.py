#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Lukas Holub (@lukasholub)
# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_eigrp
short_description: Manage EIGRP interface policies (eigrp:IfPol)
description:
- Manage EIGRP interface policies for Tenants on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing Tenant.
    type: str
    aliases: [ tenant_name ]
  eigrp:
    description:
    - The EIGRP interface policy name.
    - Note that you cannot change this name after the object has been created.
    type: str
    aliases: [ eigrp_interface, name ]
  bandwidth:
    description:
    - The EIGRP bandwidth in kbps, overrides the bandwidth configured on an interface.
    - This is used to influence path selection.
    - Accepted values range between C(0) and C(2560000000).
    - The APIC defaults to C(0) when unset during creation.
    type: int
  control_state:
    description:
    - The interface policy control state.
    - 'This is a list of one or more of the following controls:'
    - C(bfd) -- Enable Bidirectional Forwarding Detection.
    - C(nexthop_self) -- Nexthop Self.
    - C(split_horizon) -- Split Horizon.
    - C(passive) -- The interface does not participate in the EIGRP protocol and
      will not establish adjacencies or send routing updates.
    - The APIC defaults to C([split_horizon, nexthop_self]) when unset during creation.
    type: list
    elements: str
    choices: [ bfd, nexthop_self, passive, split_horizon ]
  delay:
    description:
    - The EIGRP throughput delay, overrides the delay configured on an interface.
    - This is used to influence path selection.
    - The APIC defaults to C(0) when unset during creation.
    type: int
  delay_unit:
    description:
    - The EIGRP delay units, Wide metrics can use picoseconds accuracy for delay.
    - The APIC defaults to C(tens_of_microseconds) when unset during creation.
    type: str
    choices: [ picoseconds, tens_of_microseconds ]
  hello_interval:
    description:
    - The time interval in seconds between hello packets that EIGRP sends on the interface.
    - The smaller the hello interval, the faster topological changes will be detected, but more routing traffic will ensue.
    - Accepted values range between C(1) and C(65535).
    - The APIC defaults to C(5) when unset during creation.
    type: int
  hold_interval:
    description:
    - The time period of time in seconds before declaring that the neighbor is down.
    - Accepted values range between C(1) and C(65535).
    - The APIC defaults to C(15) when unset during creation.
    type: int
  description:
    description:
    - The description of the EIGRP interface policy.
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

notes:
- The C(tenant) used must exist before using this module in your playbook.
- The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(eigrp:IfPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
- Lukas Holub (@lukasholub)
"""

EXAMPLES = r"""
- name: Create an EIGRP interface policy
  cisco.aci.aci_interface_policy_eigrp:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    eigrp: eigrp1
    bandwidth: 10000
    control_state: [split-horizon, nh-self]
    delay: 10
    delay_unit: tens_of_micro
    hello_interval: 5
    hold_interval: 15
    state: present
  delegate_to: localhost

- name: Delete EIGRRP interface policy
  cisco.aci.aci_interface_policy_eigrp:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    eigrp: eigrp1
    state: present
  delegate_to: localhost

- name: Query an EIGRRP interface policy
  cisco.aci.aci_interface_policy_eigrp:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    eigrp: eigrp1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all EIGRP interface policies in tenant production
  cisco.aci.aci_interface_policy_eigrp:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible_collections.cisco.aci.plugins.module_utils.constants import (
    MATCH_EIGRP_INTERFACE_POLICY_DELAY_UNIT_MAPPING,
    MATCH_EIGRP_INTERFACE_POLICY_CONTROL_STATE_MAPPING,
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        eigrp=dict(type="str", aliases=["eigrp_interface", "name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        bandwidth=dict(type="int"),
        control_state=dict(type="list", elements="str", choices=["bfd", "nexthop_self", "passive", "split_horizon"]),
        delay=dict(type="int"),
        delay_unit=dict(type="str", choices=["picoseconds", "tens_of_microseconds"]),
        hello_interval=dict(type="int"),
        hold_interval=dict(type="int"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["eigrp", "tenant"]],
            ["state", "present", ["eigrp", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    eigrp = module.params.get("eigrp")
    delay = module.params.get("delay")
    delay_unit = MATCH_EIGRP_INTERFACE_POLICY_DELAY_UNIT_MAPPING.get(module.params.get("delay_unit"))
    description = module.params.get("description")
    name_alias = module.params.get("name_alias")
    state = module.params.get("state")

    bandwidth = module.params.get("bandwidth")
    if bandwidth is not None and bandwidth not in range(2560000001):
        module.fail_json(msg="Parameter 'bandwidth' is only valid in range between 0 and 2560000000.")

    hello_interval = module.params.get("hello_interval")
    if hello_interval is not None and hello_interval not in range(1, 65536):
        module.fail_json(msg="Parameter 'hello_interval' is only valid in range between 1 and 65535.")

    hold_interval = module.params.get("hold_interval")
    if hold_interval is not None and hold_interval not in range(1, 65536):
        module.fail_json(msg="Parameter 'hold_interval' is only valid in range between 1 and 65535.")

    if module.params.get("control_state"):
        control_state = ",".join([MATCH_EIGRP_INTERFACE_POLICY_CONTROL_STATE_MAPPING.get(v) for v in module.params.get("control_state")])
    else:
        control_state = None

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="eigrpIfPol",
            aci_rn="eigrpIfPol-{0}".format(eigrp),
            module_object=eigrp,
            target_filter={"name": eigrp},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="eigrpIfPol",
            class_config=dict(
                name=eigrp,
                descr=description,
                bw=bandwidth,
                ctrl=control_state,
                delay=delay,
                delayUnit=delay_unit,
                helloIntvl=hello_interval,
                holdIntvl=hold_interval,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="eigrpIfPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
