#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_fabric_span_session_source_filter
version_added: "2.11.0"
short_description: Manage Fabric SPAN Sessions Source Filter on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Switched Port Analyzer (SPAN) Sessions Source Filter on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.4) and later.
- This module allows for creation and deletion only; updates are not supported.
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the template.
    - The template must be a Fabric Monitoring Access Policy template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the template.
    - The template must be a Fabric Monitoring Access Policy template.
    - This parameter or O(template) is required.
    type: str
  span_session_name:
    description:
    - The name of the SPAN Session.
    - This parameter or O(span_session_uuid) is required.
    type: str
  span_session_uuid:
    description:
    - The UUID of the SPAN Session.
    - This parameter or O(span_session_name) is required.
    type: str
  span_session_source_name:
    description:
    - The name of the SPAN Session source.
    type: str
  source_ip_prefix:
    description:
    - The source IP prefix for the SPAN Session source filter.
    - This filters traffic based on the source IP address.
    - This can be a valid IPv4 or IPv6 address.
    type: str
  destination_ip_prefix:
    description:
    - The destination IP prefix for the SPAN Session source filter.
    - This filters traffic based on the destination IP address.
    - This can be a valid IPv4 or IPv6 address.
    type: str
  source_port_from:
    description:
    - The starting source port number for the SPAN Session source filter.
    - This parameter is required to query/delete a specific SPAN session source filter when not configured with "unspecified".
    type: str
    default: unspecified
    choices: ['53', 'dns', '20', 'ftp_data', '80', 'http', '443', 'https', '110', 'pop3', '554', 'rtsp', '25', 'smtp', '22', 'ssh', '0', 'unspecified']
  source_port_to:
    description:
    - The ending source port number for the SPAN Session source filter.
    - This parameter is required to query/delete a specific SPAN session source filter when not configured with "unspecified".
    type: str
    default: unspecified
    choices: ['53', 'dns', '20', 'ftp_data', '80', 'http', '443', 'https', '110', 'pop3', '554', 'rtsp', '25', 'smtp', '22', 'ssh', '0', 'unspecified']
  destination_port_from:
    description:
    - The starting destination port number for the SPAN Session source filter.
    - This parameter is required to query/delete a specific SPAN session source filter when not configured with "unspecified".
    type: str
    default: unspecified
    choices: ['53', 'dns', '20', 'ftp_data', '80', 'http', '443', 'https', '110', 'pop3', '554', 'rtsp', '25', 'smtp', '22', 'ssh', '0', 'unspecified']
  destination_port_to:
    description:
    - The ending destination port number for the SPAN Session source filter.
    - This parameter is required to query/delete a specific SPAN session source filter when not configured with "unspecified".
    type: str
    default: unspecified
    choices: ['53', 'dns', '20', 'ftp_data', '80', 'http', '443', 'https', '110', 'pop3', '554', 'rtsp', '25', 'smtp', '22', 'ssh', '0', 'unspecified']
  ip_protocol:
    description:
    - The IP protocol for the SPAN Session source filter.
    - This filters traffic based on the Layer 3 or Layer 4 protocol.
    - This parameter is required to query/delete a specific SPAN session source filter when not configured with "unspecified".
    type: str
    choices:
      - '0'
      - 'unspecified'
      - 'egp'
      - '8'
      - 'eigrp'
      - '88'
      - 'icmp'
      - '1'
      - 'icmpv6'
      - '58'
      - 'igmp'
      - '2'
      - 'igp'
      - '9'
      - 'l2tp'
      - '115'
      - 'ospfigp'
      - '89'
      - 'pim'
      - '103'
      - 'tcp'
      - '6'
      - 'udp'
      - '17'
    default: unspecified
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Fabric Monitoring Access Policy template.
- The O(span_session_name) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_fabric_span_session) to create the Fabric SPAN Session.
- The O(span_session_source_name) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_fabric_span_session_source) to create the Fabric SPAN Session Source.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_fabric_span_session
- module: cisco.mso.ndo_fabric_span_session_source
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create SPAN Session source with IPv4 address
  cisco.mso.ndo_fabric_span_session_source_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    span_session_source_name: ansible_test_source_1
    source_ip_prefix: 1.1.1.1
    destination_ip_prefix: 2.2.2.2
    source_port_from: http
    source_port_to: https
    destination_port_from: http
    destination_port_to: https
    ip_protocol: tcp
    state: present

- name: Create SPAN Session source filter with IPv6 address
  cisco.mso.ndo_fabric_span_session_source_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    span_session_source_name: ansible_test_source_1
    source_ip_prefix: 1::1
    destination_ip_prefix: 2::2
    source_port_from: 20
    source_port_to: 22
    destination_port_from: 25
    destination_port_to: 110
    ip_protocol: 6
    state: present

- name: Query a specific SPAN Session source filter
  cisco.mso.ndo_fabric_span_session_source_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    span_session_source_name: ansible_test_source_1
    source_ip_prefix: 1.1.1.1
    destination_ip_prefix: 2.2.2.2
    source_port_from: "ftp_data"
    source_port_to: "ssh"
    destination_port_from: "smtp"
    destination_port_to: "pop3"
    ip_protocol: "tcp"
    state: query
  register: query_one

- name: Query all SPAN Session source filters
  cisco.mso.ndo_fabric_span_session_source_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    span_session_source_name: ansible_test_source_1
    state: query
  register: query_all

- name: Delete a specific SPAN Session source filter
  cisco.mso.ndo_fabric_span_session_source_filter:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    span_session_source_name: ansible_test_source_1
    source_ip_prefix: 1.1.1.1
    destination_ip_prefix: 2.2.2.2
    source_port_from: 20
    source_port_to: 22
    destination_port_from: 25
    destination_port_to: 110
    ip_protocol: 6
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.constants import PORT_MAPPING, IP_PROTOCOL_MAPPING
from collections import namedtuple
import copy


port_mapping_values = list(PORT_MAPPING) + list(PORT_MAPPING.values())
ip_protocol_mapping_values = list(IP_PROTOCOL_MAPPING) + list(IP_PROTOCOL_MAPPING.values())


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        span_session_name=dict(type="str"),
        span_session_uuid=dict(type="str"),
        span_session_source_name=dict(type="str"),
        source_ip_prefix=dict(type="str"),
        destination_ip_prefix=dict(type="str"),
        source_port_from=dict(type="str", choices=port_mapping_values, default="unspecified"),
        source_port_to=dict(type="str", choices=port_mapping_values, default="unspecified"),
        destination_port_from=dict(type="str", choices=port_mapping_values, default="unspecified"),
        destination_port_to=dict(type="str", choices=port_mapping_values, default="unspecified"),
        ip_protocol=dict(type="str", choices=ip_protocol_mapping_values, default="unspecified"),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("template", "template_id"),
            ("span_session_name", "span_session_uuid"),
        ],
        required_if=[
            ["state", "absent", ["span_session_source_name", "source_ip_prefix", "destination_ip_prefix"]],
            ["state", "present", ["span_session_source_name", "source_ip_prefix", "destination_ip_prefix"]],
        ],
        required_one_of=[
            ["template", "template_id"],
            ["span_session_name", "span_session_uuid"],
        ],
    )

    mso = MSOModule(module)

    template_name = module.params.get("template")
    template_id = module.params.get("template_id")
    span_session_name = module.params.get("span_session_name")
    span_session_uuid = module.params.get("span_session_uuid")
    span_session_source_name = module.params.get("span_session_source_name")
    source_ip_prefix = module.params.get("source_ip_prefix")
    destination_ip_prefix = module.params.get("destination_ip_prefix")
    source_port_from = int(PORT_MAPPING.get(module.params.get("source_port_from"), module.params.get("source_port_from")))
    source_port_to = int(PORT_MAPPING.get(module.params.get("source_port_to"), module.params.get("source_port_to")))
    destination_port_from = int(PORT_MAPPING.get(module.params.get("destination_port_from"), module.params.get("destination_port_from")))
    destination_port_to = int(PORT_MAPPING.get(module.params.get("destination_port_to"), module.params.get("destination_port_to")))
    ip_protocol = IP_PROTOCOL_MAPPING.get(module.params.get("ip_protocol"), module.params.get("ip_protocol"))
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "monitoring_tenant", template_name, template_id)
    mso_template.validate_template("monitoring")

    fabric_span_session = mso_template.get_fabric_span_session(span_session_uuid, span_session_name, fail_module=True)
    span_session_source = mso_template.get_fabric_span_session_source(
        span_session_source_name, fabric_span_session.details.get("sourceGroup", {}).get("sources", []), fail_module=True
    )

    match = get_fabric_span_session_source_filter(mso_template, module.params, span_session_source.details.get("filters"))

    filter_object_full_config = dict(
        templateId=mso_template.template_id,
        templateName=mso_template.template_name,
        spanSessionName=fabric_span_session.details.get("name"),
        spanSessionUUID=fabric_span_session.details.get("uuid"),
        spanSessionSourceName=span_session_source.details.get("name"),
    )

    if match and source_ip_prefix and destination_ip_prefix:
        match.details.update(filter_object_full_config)
        mso.existing = mso.previous = copy.copy(match.details)  # Query a specific object
    elif match:
        for filter in match:
            filter.update(filter_object_full_config)
        mso.existing = match  # Query all objects

    if state != "query":
        span_session_source_filter_path = "/monitoringTemplate/template/spanSessions/{0}/sourceGroup/sources/{1}/filters/{2}".format(
            fabric_span_session.index, span_session_source.index, match.index if match else "-"
        )

    ops = []

    if state == "present" and not match:
        mso_values = dict(
            srcIPPrefix=source_ip_prefix,
            srcPortFrom=source_port_from,
            srcPortTo=source_port_to,
            destIPPrefix=destination_ip_prefix,
            destPortFrom=destination_port_from,
            destPortTo=destination_port_to,
            ipProtocol=ip_protocol,
        )

        mso.sanitize(copy.copy(mso_values))
        ops.append(dict(op="add", path=span_session_source_filter_path, value=mso_values))

    elif state == "absent" and match:
        ops.append(dict(op="remove", path=span_session_source_filter_path))

    if not module.check_mode and ops:
        if state == "present" and not match or state == "absent" and match:
            mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
            fabric_span_session = mso_template.get_fabric_span_session(span_session_uuid, span_session_name, fail_module=True)
            span_session_source = mso_template.get_fabric_span_session_source(
                span_session_source_name, fabric_span_session.details.get("sourceGroup", {}).get("sources", []), fail_module=True
            )
            match = get_fabric_span_session_source_filter(mso_template, module.params, span_session_source.details.get("filters"))
            if match:
                match.details.update(filter_object_full_config)
                mso.existing = match.details  # When the state is present
            else:
                mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        if state == "present":
            mso.existing = copy.copy(mso.proposed)
            mso.existing.update(filter_object_full_config)
        else:
            mso.existing = {}

    mso.exit_json()


def get_fabric_span_session_source_filter(mso_template, filter_config, search_list, fail_module=False):
    KVPair = namedtuple("KVPair", "key value")
    if filter_config and filter_config.get("source_ip_prefix") and filter_config.get("destination_ip_prefix") and search_list:  # Query a specific object
        KVPairs = [
            KVPair("srcIPPrefix", filter_config.get("source_ip_prefix")),
            KVPair("srcPortFrom", int(PORT_MAPPING.get(filter_config.get("source_port_from"), filter_config.get("source_port_from")))),
            KVPair("srcPortTo", int(PORT_MAPPING.get(filter_config.get("source_port_to"), filter_config.get("source_port_to")))),
            KVPair("destIPPrefix", filter_config.get("destination_ip_prefix")),
            KVPair("destPortFrom", int(PORT_MAPPING.get(filter_config.get("destination_port_from"), filter_config.get("destination_port_from")))),
            KVPair("destPortTo", int(PORT_MAPPING.get(filter_config.get("destination_port_to"), filter_config.get("destination_port_to")))),
            KVPair("ipProtocol", IP_PROTOCOL_MAPPING.get(filter_config.get("ip_protocol"), filter_config.get("ip_protocol"))),
        ]
        return mso_template.get_object_by_key_value_pairs("SPAN Session Source Filter", search_list, KVPairs, fail_module)
    return search_list  # Query all objects


if __name__ == "__main__":
    main()
