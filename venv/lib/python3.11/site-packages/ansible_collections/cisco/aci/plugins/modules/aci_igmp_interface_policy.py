#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_igmp_interface_policy
short_description: Manage IGMP Interface Policies (igmp:IfPol)
description:
- Manage IGMP Interface Policies on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the IGMP Interface Policy.
    type: str
  tenant:
    description:
    - The tenant to build the IGMP Interface Policy under.
    type: str
  description:
    description:
    - The description of the IGMP Interface Policy.
    type: str
  group_timeout:
    description:
    - The IGMP group timeout in seconds.
    - The APIC defaults to 260 when unset during creation.
    type: int
  query_interval:
    description:
    - The IGMP query interval in seconds.
    - The APIC defaults to 125 when unset during creation.
    type: int
  query_response_interval:
    description:
    - The IGMP query response interval in seconds.
    - The APIC defaults to 10 when unset during creation.
    type: int
  last_member_count:
    description:
    - The last member query count.
    - The APIC defaults to 2 when unset during creation.
    type: int
  last_member_response:
    description:
    - The last member response time in seconds.
    - The APIC defaults to 1 when unset during creation.
    type: int
  startup_query_count:
    description:
    - The Startup Query Count.
    - The APIC defaults to 2 when unset during creation.
    type: int
  startup_query_interval:
    description:
    - The startup query interval in seconds.
    - The APIC defaults to 31 when unset during creation.
    type: int
  querier_timeout:
    description:
    - The querier timeout in seconds.
    - The APIC defaults to 255 when unset during creation.
    type: int
  robustness_variable:
    description:
    - The robustness factor.
    - The APIC defaults to 2 when unset during creation.
    type: int
  igmp_version:
    description:
    - The IGMP version to run.
    - The APIC defaults to v2 when unset during creation.
    type: str
    choices: [ v2, v3 ]
  allow_v3_asm:
    description:
    - Enable the Allow v3 ASM option.
    - The APIC defaults to False when unset during creation.
    - If this parameter is set, fast_leave and report_link_local_groups must also be set.
    type: bool
  fast_leave:
    description:
    - Enable the Fast Leave option.
    - The APIC defaults to False when unset during creation.
    - If this parameter is set, allow_v3_asm and report_link_local_groups must also be set.
    type: bool
  report_link_local_groups:
    description:
    - Enable the Report Link Local Groups option.
    - The APIC defaults to False when unset during creation.
    - If this parameter is set, allow_v3_asm and fast_leave must also be set.
    type: bool
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(igmp:IfPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/

author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add an IGMP Interface Policy
  cisco.aci.aci_igmp_interface_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_igmp_intf_pol
    query_interval: 200
    state: present
  delegate_to: localhost

- name: Query an IGMP Interface Policy
  cisco.aci.aci_igmp_interface_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_igmp_intf_pol
    state: query
  delegate_to: localhost

- name: Query all IGMP Interface Policies
  cisco.aci.aci_igmp_interface_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove an IGMP Interface Policy
  cisco.aci.aci_igmp_interface_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ans_igmp_intf_pol
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
        name=dict(type="str"),
        tenant=dict(type="str"),
        description=dict(type="str"),
        group_timeout=dict(type="int"),
        query_interval=dict(type="int"),
        query_response_interval=dict(type="int"),
        last_member_count=dict(type="int"),
        last_member_response=dict(type="int"),
        startup_query_count=dict(type="int"),
        startup_query_interval=dict(type="int"),
        querier_timeout=dict(type="int"),
        robustness_variable=dict(type="int"),
        igmp_version=dict(type="str", choices=["v2", "v3"]),
        allow_v3_asm=dict(type="bool"),
        fast_leave=dict(type="bool"),
        report_link_local_groups=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["name", "tenant"]],
            ["state", "absent", ["name", "tenant"]],
        ],
        required_together=[
            ["allow_v3_asm", "fast_leave", "report_link_local_groups"],
        ],
    )

    aci = ACIModule(module)

    name = module.params.get("name")
    tenant = module.params.get("tenant")
    description = module.params.get("description")
    group_timeout = module.params.get("group_timeout")
    query_interval = module.params.get("query_interval")
    query_response_interval = module.params.get("query_response_interval")
    last_member_count = module.params.get("last_member_count")
    last_member_response = module.params.get("last_member_response")
    startup_query_count = module.params.get("startup_query_count")
    startup_query_interval = module.params.get("startup_query_interval")
    querier_timeout = module.params.get("querier_timeout")
    robustness_variable = module.params.get("robustness_variable")
    igmp_version = module.params.get("igmp_version")
    allow_v3_asm = module.params.get("allow_v3_asm")
    fast_leave = module.params.get("fast_leave")
    report_link_local_groups = module.params.get("report_link_local_groups")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="igmpIfPol",
            aci_rn="igmpIfPol-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )
    aci.get_existing()

    if state == "present":
        if allow_v3_asm is not None:
            if_ctrl_list = []
            if allow_v3_asm:
                if_ctrl_list.append("allow-v3-asm")
            if fast_leave:
                if_ctrl_list.append("fast-leave")
            if report_link_local_groups:
                if_ctrl_list.append("rep-ll")
            if_ctrl = ",".join(if_ctrl_list)
        else:
            if_ctrl = None

        aci.payload(
            aci_class="igmpIfPol",
            class_config=dict(
                name=name,
                descr=description,
                grpTimeout=group_timeout,
                ifCtrl=if_ctrl,
                lastMbrCnt=last_member_count,
                lastMbrRespTime=last_member_response,
                querierTimeout=querier_timeout,
                queryIntvl=query_interval,
                robustFac=robustness_variable,
                rspIntvl=query_response_interval,
                startQueryCnt=startup_query_count,
                startQueryIntvl=startup_query_interval,
                ver=igmp_version,
            ),
        )

        aci.get_diff(aci_class="igmpIfPol")
        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
