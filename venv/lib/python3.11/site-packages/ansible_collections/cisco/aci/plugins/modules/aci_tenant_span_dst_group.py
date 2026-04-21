#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_tenant_span_dst_group
short_description: Manage SPAN destination groups (span:DestGrp)
description:
- Manage SPAN destination groups on Cisco ACI fabrics.
options:
  destination_group:
    description:
    - The name of the SPAN destination group.
    type: str
    aliases: [ name, dst_group ]
  description:
    description:
    - The description of the SPAN destination group.
    type: str
    aliases: [ descr ]
  tenant:
    description:
    - The name of the tenant.
    type: str
    aliases: [ tenant_name ]
  destination_epg:
    description:
    - The destination end point group.
    type: dict
    suboptions:
      epg:
        description:
        - The name of the end point group.
        type: str
      ap:
        description:
        - The name of application profile.
        type: str
      tenant:
        description:
        - The name of the tenant.
        type: str
        aliases: [ tenant_name ]
  source_ip:
    description:
    - The source IP address or prefix.
    type: str
  destination_ip:
    description:
    - The destination IP address.
    type: str
  span_version:
    description:
    - SPAN version.
    type: str
    choices: [ version_1, version_2 ]
  flow_id:
    description:
    - The flow ID of the SPAN packet.
    type: int
  ttl:
    description:
    - The time to live of the span session packets.
    type: int
  mtu:
    description:
    - The MTU truncation size for the packets.
    type: int
  dscp:
    description:
    - The DSCP value for sending the monitored packets using ERSPAN.
    type: str
    choices: [ CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, unspecified ]
  version_enforced:
    description:
    - Enforce SPAN version.
    type: bool
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
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(span:DestGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dag Wieers (@dagwieers)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add SPAN destination group
  cisco.aci.aci_tenant_span_dst_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: Tenant1
    destination_epg:
      tenant: Test1
      ap: ap1
      epg: ep1
    destination_group: group1
    description: Test span
    destination_ip: 10.0.0.1
    source_ip: 10.0.2.1
    version_enforced: false
    span_version: version_1
    ttl: 2
    mtu: 1500
    flow_id: 1
    dscp: CS1
    state: present
  delegate_to: localhost

- name: Remove SPAN destination group
  cisco.aci.aci_tenant_span_dst_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: Tenant1
    destination_group: group1
    state: absent
  delegate_to: localhost

- name: Query SPAN destination group
  cisco.aci.aci_tenant_span_dst_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: Tenant1
    destination_group: group1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all SPAN destination groups
  cisco.aci.aci_tenant_span_dst_group:
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def destination_epg_spec():
    return dict(
        epg=dict(type="str"),
        ap=dict(type="str"),
        tenant=dict(type="str", aliases=["tenant_name"]),
    )


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        destination_epg=dict(type="dict", options=destination_epg_spec()),
        destination_group=dict(type="str", aliases=["name", "dst_group"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        name_alias=dict(type="str"),
        source_ip=dict(type="str"),
        destination_ip=dict(type="str"),
        mtu=dict(type="int"),
        ttl=dict(type="int"),
        flow_id=dict(type="int"),
        version_enforced=dict(type="bool"),
        span_version=dict(type="str", choices=["version_1", "version_2"]),
        dscp=dict(
            type="str",
            choices=[
                "CS0",
                "CS1",
                "CS2",
                "CS3",
                "CS4",
                "CS5",
                "CS6",
                "CS7",
                "EF",
                "VA",
                "AF11",
                "AF12",
                "AF13",
                "AF21",
                "AF22",
                "AF23",
                "AF31",
                "AF32",
                "AF33",
                "AF41",
                "AF42",
                "AF43",
                "unspecified",
            ],
        ),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["destination_group", "tenant"]],
            ["state", "present", ["destination_group", "destination_ip", "source_ip", "destination_epg", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    destination_epg = module.params.get("destination_epg")
    destination_group = module.params.get("destination_group")
    description = module.params.get("description")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    destination_ip = module.params.get("destination_ip")
    source_ip = module.params.get("source_ip")
    span_version = module.params.get("span_version")
    name_alias = module.params.get("name_alias")
    dscp = module.params.get("dscp")
    mtu = str(module.params.get("mtu"))
    ttl = str(module.params.get("ttl"))
    flow_id = str(module.params.get("flow_id"))
    version_enforced = module.params.get("version_enforced")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="spanDestGrp",
            aci_rn="destgrp-{0}".format(destination_group),
            module_object=destination_group,
            target_filter={"name": destination_group},
        ),
        child_classes=["spanDest", "spanRsDestEpg"],
    )

    aci.get_existing()

    if state == "present":
        dest_tdn = "uni/tn-{0}/ap-{1}/epg-{2}".format(destination_epg["tenant"], destination_epg["ap"], destination_epg["epg"])

        if version_enforced is True:
            version_enforced = "yes"
        else:
            version_enforced = "no"

        if span_version == "version_1":
            span_version = "ver1"
        else:
            span_version = "ver2"

        child_configs = [
            dict(
                spanDest=dict(
                    attributes=dict(name=destination_group),
                    children=[
                        dict(
                            spanRsDestEpg=dict(
                                attributes=dict(
                                    ip=destination_ip,
                                    srcIpPrefix=source_ip,
                                    ver=span_version,
                                    verEnforced=version_enforced,
                                    ttl=ttl,
                                    mtu=mtu,
                                    flowId=flow_id,
                                    dscp=dscp,
                                    tDn=dest_tdn,
                                )
                            )
                        )
                    ],
                )
            ),
        ]

        aci.payload(
            aci_class="spanDestGrp",
            class_config=dict(
                name=destination_group,
                descr=description,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="spanDestGrp")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
