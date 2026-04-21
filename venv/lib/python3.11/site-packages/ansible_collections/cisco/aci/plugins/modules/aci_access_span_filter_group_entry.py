#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Akini Ross <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_access_span_filter_group_entry
short_description: Manage Access SPAN filter group entries (span:FilterEntry)
description:
- Manage Access SPAN filter group entries on Cisco ACI fabrics.
options:
  filter_group:
    description:
    - The name of the Access SPAN filter group.
    type: str
  source_ip:
    description:
    - The source IP Prefix.
    type: str
  destination_ip:
    description:
    - The destination IP Prefix.
    type: str
  first_src_port:
    description:
    - The first source port (from port).
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
  last_src_port:
    description:
    - The last source port (to port).
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
  first_dest_port:
    description:
    - The first destination port (from port).
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
  last_dest_port:
    description:
    - The last destination port (to port).
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
  ip_protocol:
    description:
    - The IP Protocol.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ eigrp, egp, icmp, icmpv6, igmp, igp, l2tp, ospfigp, pim, tcp, udp, unspecified ]
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

notes:
- The C(filter_group) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_access_span_filter_group) module can be used for this.
seealso:
- module: cisco.aci.aci_access_span_filter_group
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(span:FilterEntry).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a Access SPAN filter entry
  cisco.aci.aci_access_span_filter_group_entry:
    host: apic
    username: admin
    password: SomeSecretPassword
    filter_group: group1
    source_ip: 1.1.1.1
    destination_ip: 2.2.2.2
    state: present
  delegate_to: localhost

- name: Remove a Access SPAN filter entry
  cisco.aci.aci_access_span_filter_group_entry:
    host: apic
    username: admin
    password: SomeSecretPassword
    filter_group: group1
    source_ip: 1.1.1.1
    destination_ip: 2.2.2.2
    state: absent
  delegate_to: localhost

- name: Query a Access SPAN filter group
  cisco.aci.aci_access_span_filter_group_entry:
    host: apic
    username: admin
    password: SomeSecretPassword
    filter_group: group1
    source_ip: 1.1.1.1
    destination_ip: 2.2.2.2
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Access SPAN filter groups
  cisco.aci.aci_access_span_filter_group_entry:
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import VALID_IP_PROTOCOLS, FILTER_PORT_MAPPING


def get_port_value(port):
    return FILTER_PORT_MAPPING.get(port, port) if port else "unspecified"


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        filter_group=dict(type="str"),  # Not required for querying all objects
        source_ip=dict(type="str"),  # Not required for querying all objects
        destination_ip=dict(type="str"),  # Not required for querying all objects
        first_src_port=dict(type="str"),
        last_src_port=dict(type="str"),
        first_dest_port=dict(type="str"),
        last_dest_port=dict(type="str"),
        ip_protocol=dict(type="str", choices=VALID_IP_PROTOCOLS),
        name_alias=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["filter_group", "source_ip", "destination_ip"]],
            ["state", "present", ["filter_group", "source_ip", "destination_ip"]],
        ],
    )

    aci = ACIModule(module)

    filter_group = module.params.get("filter_group")
    source_ip = module.params.get("source_ip")
    destination_ip = module.params.get("destination_ip")
    first_src_port = module.params.get("first_src_port")
    last_src_port = module.params.get("last_src_port")
    first_dest_port = module.params.get("first_dest_port")
    last_dest_port = module.params.get("last_dest_port")
    ip_protocol = module.params.get("ip_protocol")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci.construct_url(
        root_class=dict(
            aci_class="infra",
            aci_rn="infra",
        ),
        subclass_1=dict(
            aci_class="spanFilterGrp",
            aci_rn="filtergrp-{0}".format(filter_group),
            module_object=filter_group,
            target_filter={"name": filter_group},
        ),
        subclass_2=dict(
            aci_class="spanFilterEntry",
            aci_rn="proto-{0}-src-[{1}]-dst-[{2}]-srcPortFrom-{3}-srcPortTo-{4}-dstPortFrom-{5}-dstPortTo-{6}".format(
                ip_protocol if module.params.get("ip_protocol") else "unspecified",
                source_ip,
                destination_ip,
                get_port_value(first_src_port),
                get_port_value(last_src_port),
                get_port_value(first_dest_port),
                get_port_value(last_dest_port),
            ),
            target_filter={
                "dstAddr": destination_ip,
                "dstPortFrom": first_dest_port,
                "dstPortTo": last_dest_port,
                "ipProto": ip_protocol,
                "srcAddr": source_ip,
                "srcPortFrom": first_src_port,
                "srcPortTo": last_src_port,
            },
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="spanFilterEntry",
            class_config=dict(
                dstAddr=destination_ip,
                dstPortFrom=first_dest_port,
                dstPortTo=last_dest_port,
                ipProto=ip_protocol,
                nameAlias=name_alias,
                srcAddr=source_ip,
                srcPortFrom=first_src_port,
                srcPortTo=last_src_port,
            ),
        )

        aci.get_diff(aci_class="spanFilterEntry")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
