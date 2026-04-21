#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_filter_entry
short_description: Manage filter entries (vz:Entry)
description:
- Manage filter entries for a filter on Cisco ACI fabrics.
options:
  arp_flag:
    description:
    - The arp flag to use when the ether_type is arp.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ arp_reply, arp_request, unspecified ]
  description:
    description:
    - Description for the Filter Entry.
    type: str
    aliases: [ descr ]
  destination_port:
    description:
    - Used to set both destination start and end ports to the same value when ip_protocol is tcp or udp.
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    aliases: [ dst_port ]
  destination_port_end:
    description:
    - Used to set the destination end port when ip_protocol is tcp or udp.
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    aliases: [ dst_port_end ]
  destination_port_start:
    description:
    - Used to set the destination start port when ip_protocol is tcp or udp.
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    aliases: [ dst_port_start ]
  source_port:
    description:
    - Used to set both source start and end ports to the same value when ip_protocol is tcp or udp.
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    aliases: [ src_port ]
  source_port_end:
    description:
    - Used to set the source end port when ip_protocol is tcp or udp.
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    aliases: [ src_port_end ]
  source_port_start:
    description:
    - Used to set the source start port when ip_protocol is tcp or udp.
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    aliases: [ src_port_start ]
  tcp_flags:
    description:
    - The TCP flags of the filter entry.
    - The TCP C(established) cannot be combined with other tcp rules.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: list
    elements: str
    choices: [ acknowledgment, established, finish, reset, synchronize, unspecified ]
  match_only_fragments:
    description:
    - The match only packet fragments of the filter entry.
    - When enabled C(true) the rule applies to any fragments with offset greater than 0 (all fragments except first).
    - When disabled C(false) it applies to all packets (including all fragments)
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  entry:
    description:
    - Then name of the Filter Entry.
    type: str
    aliases: [ entry_name, filter_entry, name ]
  ether_type:
    description:
    - The Ethernet type.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ arp, fcoe, ip, ipv4, ipv6, mac_security, mpls_ucast, trill, unspecified ]
  filter:
    description:
    - The name of Filter that the entry should belong to.
    type: str
    aliases: [ filter_name ]
  icmp_msg_type:
    description:
    - ICMPv4 message type; used when ip_protocol is icmp.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ dst_unreachable, echo, echo_reply, src_quench, time_exceeded, unspecified ]
  icmp6_msg_type:
    description:
    - ICMPv6 message type; used when ip_protocol is icmpv6.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ dst_unreachable, echo_request, echo_reply, neighbor_advertisement, neighbor_solicitation, redirect, time_exceeded, unspecified ]
  ip_protocol:
    description:
    - The IP Protocol type when ether_type is ip.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ eigrp, egp, icmp, icmpv6, igmp, igp, l2tp, ospfigp, pim, tcp, udp, unspecified ]
  state:
    description:
    - present, absent, query
    type: str
    default: present
    choices: [ absent, present, query ]
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
  stateful:
    description:
    - Determines the statefulness of the filter entry.
    type: bool
  tenant:
    description:
    - The name of the tenant.
    type: str
    aliases: [ tenant_name ]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(tenant) and C(filter) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_filter) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_filter
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vz:Entry).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
"""

EXAMPLES = r"""
- name: Create a filter entry
  cisco.aci.aci_filter_entry:
    host: apic
    username: admin
    password: SomeSecretPassword
    entry: https_allow
    filter: web_filter
    tenant: prod
    ether_type: ip
    ip_protocol: tcp
    dst_port_start: 443
    dst_port_end: 443
    source_port_start: 20
    source_port_end: 22
    tcp_flags:
      - acknowledgment
      - finish
    state: present
  delegate_to: localhost

- name: Create a filter entry with the match only packet fragments enabled
  cisco.aci.aci_filter_entry:
    host: apic
    username: admin
    password: SomeSecretPassword
    entry: https_allow
    filter: web_filter
    tenant: prod
    ether_type: ip
    ip_protocol: tcp
    match_only_fragments: true
    state: present
  delegate_to: localhost

- name: Delete a filter entry
  cisco.aci.aci_filter_entry:
    host: apic
    username: admin
    password: SomeSecretPassword
    entry: https_allow
    filter: web_filter
    tenant: prod
    state: absent
  delegate_to: localhost

- name: Query all filter entries
  cisco.aci.aci_filter_entry:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific filter entry
  cisco.aci.aci_filter_entry:
    host: apic
    username: admin
    password: SomeSecretPassword
    entry: https_allow
    filter: web_filter
    tenant: prod
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import (
    VALID_IP_PROTOCOLS,
    FILTER_PORT_MAPPING,
    VALID_ETHER_TYPES,
    ARP_FLAG_MAPPING,
    ICMP4_MAPPING,
    ICMP6_MAPPING,
    TCP_FLAGS,
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        arp_flag=dict(type="str", choices=list(ARP_FLAG_MAPPING.keys())),
        description=dict(type="str", aliases=["descr"]),
        destination_port=dict(type="str", aliases=["dst_port"]),
        destination_port_end=dict(type="str", aliases=["dst_port_end"]),
        destination_port_start=dict(type="str", aliases=["dst_port_start"]),
        source_port=dict(type="str", aliases=["src_port"]),
        source_port_end=dict(type="str", aliases=["src_port_end"]),
        source_port_start=dict(type="str", aliases=["src_port_start"]),
        tcp_flags=dict(type="list", elements="str", choices=list(TCP_FLAGS.keys())),
        match_only_fragments=dict(type="bool"),
        entry=dict(type="str", aliases=["entry_name", "filter_entry", "name"]),  # Not required for querying all objects
        ether_type=dict(choices=VALID_ETHER_TYPES, type="str"),
        filter=dict(type="str", aliases=["filter_name"]),  # Not required for querying all objects
        icmp_msg_type=dict(type="str", choices=list(ICMP4_MAPPING.keys())),
        icmp6_msg_type=dict(type="str", choices=list(ICMP6_MAPPING.keys())),
        ip_protocol=dict(choices=VALID_IP_PROTOCOLS, type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        stateful=dict(type="bool"),
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["entry", "filter", "tenant"]],
            ["state", "present", ["entry", "filter", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    arp_flag = module.params.get("arp_flag")
    if arp_flag is not None:
        arp_flag = ARP_FLAG_MAPPING.get(arp_flag)
    description = module.params.get("description")
    dst_port = module.params.get("destination_port")
    if FILTER_PORT_MAPPING.get(dst_port) is not None:
        dst_port = FILTER_PORT_MAPPING.get(dst_port)
    dst_port_end = module.params.get("destination_port_end")
    if FILTER_PORT_MAPPING.get(dst_port_end) is not None:
        dst_port_end = FILTER_PORT_MAPPING.get(dst_port_end)
    dst_port_start = module.params.get("destination_port_start")
    if FILTER_PORT_MAPPING.get(dst_port_start) is not None:
        dst_port_start = FILTER_PORT_MAPPING.get(dst_port_start)
    entry = module.params.get("entry")
    ether_type = module.params.get("ether_type")
    filter_name = module.params.get("filter")
    icmp_msg_type = module.params.get("icmp_msg_type")
    if icmp_msg_type is not None:
        icmp_msg_type = ICMP4_MAPPING.get(icmp_msg_type)
    icmp6_msg_type = module.params.get("icmp6_msg_type")
    if icmp6_msg_type is not None:
        icmp6_msg_type = ICMP6_MAPPING.get(icmp6_msg_type)
    ip_protocol = module.params.get("ip_protocol")
    state = module.params.get("state")
    stateful = aci.boolean(module.params.get("stateful"))
    tenant = module.params.get("tenant")
    name_alias = module.params.get("name_alias")

    source_port = module.params.get("source_port")
    if FILTER_PORT_MAPPING.get(source_port) is not None:
        source_port = FILTER_PORT_MAPPING.get(source_port)
    source_port_end = module.params.get("source_port_end")
    if FILTER_PORT_MAPPING.get(source_port_end) is not None:
        source_port_end = FILTER_PORT_MAPPING.get(source_port_end)
    source_port_start = module.params.get("source_port_start")
    if FILTER_PORT_MAPPING.get(source_port_start) is not None:
        source_port_start = FILTER_PORT_MAPPING.get(source_port_start)

    # validate that dst_port is not passed with dst_port_end or dst_port_start
    if dst_port is not None and (dst_port_end is not None or dst_port_start is not None):
        module.fail_json(msg="Parameter 'dst_port' cannot be used with 'dst_port_end' and 'dst_port_start'")
    elif dst_port_end is not None and dst_port_start is None:
        module.fail_json(msg="Parameter 'dst_port_end' cannot be configured when the 'dst_port_start' is not defined")
    elif dst_port is not None:
        dst_port_end = dst_port
        dst_port_start = dst_port

    # validate that source_port is not passed with source_port_end or source_port_start
    if source_port is not None and (source_port_end is not None or source_port_start is not None):
        module.fail_json(msg="Parameter 'source_port' cannot be used with 'source_port_end' and 'source_port_start'")
    elif source_port_end is not None and source_port_start is None:
        module.fail_json(msg="Parameter 'source_port_end' cannot be configured when the 'source_port_start' is not defined")
    elif source_port is not None:
        source_port_end = source_port
        source_port_start = source_port

    tcp_flags = module.params.get("tcp_flags")
    tcp_flags_list = list()
    if tcp_flags is not None:
        if len(tcp_flags) >= 2 and "established" in tcp_flags:
            module.fail_json(msg="TCP established cannot be combined with other tcp rules")
        else:
            for tcp_flag in tcp_flags:
                tcp_flags_list.append(TCP_FLAGS.get(tcp_flag))

    match_only_fragments = aci.boolean(module.params.get("match_only_fragments"))
    if match_only_fragments == "yes" and (dst_port or source_port or source_port_start or source_port_end or dst_port_start or dst_port_end):
        module.fail_json(msg="Parameter 'match_only_fragments' cannot be used with 'Layer 4 Port' value")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vzFilter",
            aci_rn="flt-{0}".format(filter_name),
            module_object=filter_name,
            target_filter={"name": filter_name},
        ),
        subclass_2=dict(
            aci_class="vzEntry",
            aci_rn="e-{0}".format(entry),
            module_object=entry,
            target_filter={"name": entry},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="vzEntry",
            class_config=dict(
                arpOpc=arp_flag,
                descr=description,
                dFromPort=dst_port_start,
                dToPort=dst_port_end,
                etherT=ether_type,
                icmpv4T=icmp_msg_type,
                icmpv6T=icmp6_msg_type,
                name=entry,
                prot=ip_protocol,
                stateful=stateful,
                nameAlias=name_alias,
                applyToFrag=match_only_fragments,
                sFromPort=source_port_start,
                sToPort=source_port_end,
                tcpRules=",".join(tcp_flags_list),
            ),
        )

        aci.get_diff(aci_class="vzEntry")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
