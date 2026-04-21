#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_filter_entry
short_description: Manage filter entries in schema templates
description:
- Manage filter entries in schema templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
- Anvitha Jain (@anvitha-jain)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template.
    type: str
    required: true
  filter:
    description:
    - The name of the filter to manage.
    - There should be no space in the filter name. APIC will throw an error if a space is provided in the filter name.
    - See the C(filter_display_name) attribute if you want the display name of the filter to contain a space.
    type: str
    required: true
  filter_description:
    description:
    - The description of this filter is supported on versions of MSO that are 3.3 or greater.
    type: str
    default: ''
  filter_display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  entry:
    description:
    - The filter entry name to manage.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
    aliases: [ entry_display_name ]
  filter_entry_description:
    description:
    - The description of this filter entry.
    type: str
    aliases: [ entry_description, description ]
    default: ''
  ethertype:
    description:
    - The ethernet type to use for this filter entry.
    type: str
    choices: [ arp, fcoe, ip, ipv4, ipv6, mac-security, mpls-unicast, trill, unspecified ]
  ip_protocol:
    description:
    - The IP protocol to use for this filter entry.
    type: str
    choices: [ eigrp, egp, icmp, icmpv6, igmp, igp, l2tp, ospfigp, pim, tcp, udp, unspecified ]
  tcp_session_rules:
    description:
    - A list of TCP session rules.
    type: list
    elements: str
    choices: [ acknowledgement, established, finish, synchronize, reset, unspecified ]
  source_from:
    description:
    - The source port range from.
    type: str
  source_to:
    description:
    - The source port range to.
    type: str
  destination_from:
    description:
    - The destination port range from.
    type: str
  destination_to:
    description:
    - The destination port range to.
    type: str
  arp_flag:
    description:
    - The ARP flag to use for this filter entry.
    type: str
    choices: [ reply, request, unspecified ]
  stateful:
    description:
    - Whether this filter entry is stateful.
    type: bool
  fragments_only:
    description:
    - Whether this filter entry only matches fragments.
    type: bool
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_contract_filter
notes:
- Due to restrictions of the MSO REST API this module creates filters when needed, and removes them when the last entry has been removed.
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new filter entry
  cisco.mso.mso_schema_template_filter_entry:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    filter: Filter 1
    state: present

- name: Remove a filter entry
  cisco.mso.mso_schema_template_filter_entry:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    filter: Filter 1
    state: absent

- name: Query a specific filter entry
  cisco.mso.mso_schema_template_filter_entry:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    filter: Filter 1
    state: query
  register: query_result

- name: Query all filter entries
  cisco.mso.mso_schema_template_filter_entry:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        filter=dict(type="str", required=True),
        filter_description=dict(type="str", default=""),
        filter_display_name=dict(type="str"),
        entry=dict(type="str", aliases=["name"]),  # This parameter is not required for querying all objects
        filter_entry_description=dict(type="str", default="", aliases=["entry_description", "description"]),
        display_name=dict(type="str", aliases=["entry_display_name"]),
        ethertype=dict(type="str", choices=["arp", "fcoe", "ip", "ipv4", "ipv6", "mac-security", "mpls-unicast", "trill", "unspecified"]),
        ip_protocol=dict(type="str", choices=["eigrp", "egp", "icmp", "icmpv6", "igmp", "igp", "l2tp", "ospfigp", "pim", "tcp", "udp", "unspecified"]),
        tcp_session_rules=dict(type="list", elements="str", choices=["acknowledgement", "established", "finish", "synchronize", "reset", "unspecified"]),
        source_from=dict(type="str"),
        source_to=dict(type="str"),
        destination_from=dict(type="str"),
        destination_to=dict(type="str"),
        arp_flag=dict(type="str", choices=["reply", "request", "unspecified"]),
        stateful=dict(type="bool"),
        fragments_only=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["entry"]],
            ["state", "present", ["entry"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    filter_name = module.params.get("filter")
    filter_display_name = module.params.get("filter_display_name")
    filter_description = module.params.get("filter_description")
    entry = module.params.get("entry")
    display_name = module.params.get("display_name")
    filter_entry_description = module.params.get("filter_entry_description")
    ethertype = module.params.get("ethertype")
    ip_protocol = module.params.get("ip_protocol")
    tcp_session_rules = module.params.get("tcp_session_rules")
    source_from = module.params.get("source_from")
    source_to = module.params.get("source_to")
    destination_from = module.params.get("destination_from")
    destination_to = module.params.get("destination_to")
    arp_flag = module.params.get("arp_flag")
    if arp_flag == "request":
        arp_flag = "req"
    stateful = module.params.get("stateful")
    fragments_only = module.params.get("fragments_only")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(
            msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template, templates=", ".join(templates))
        )
    template_idx = templates.index(template)

    # Get filters
    mso.existing = {}
    filter_idx = None
    entry_idx = None
    filters = [f.get("name") for f in schema_obj.get("templates")[template_idx]["filters"]]
    if filter_name in filters:
        filter_idx = filters.index(filter_name)

        entries = [f.get("name") for f in schema_obj.get("templates")[template_idx]["filters"][filter_idx]["entries"]]
        if entry in entries:
            entry_idx = entries.index(entry)
            mso.existing = schema_obj.get("templates")[template_idx]["filters"][filter_idx]["entries"][entry_idx]

    if state == "query":
        if entry is None:
            if filter_idx is None:
                mso.fail_json(msg="Filter '{filter}' not found".format(filter=filter_name))
            mso.existing = schema_obj.get("templates")[template_idx]["filters"][filter_idx]["entries"]
        elif not mso.existing:
            mso.fail_json(msg="Entry '{entry}' not found".format(entry=entry))
        mso.exit_json()

    filters_path = "/templates/{0}/filters".format(template)
    filter_path = "/templates/{0}/filters/{1}".format(template, filter_name)
    entries_path = "/templates/{0}/filters/{1}/entries".format(template, filter_name)
    entry_path = "/templates/{0}/filters/{1}/entries/{2}".format(template, filter_name, entry)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        mso.proposed = mso.sent = {}

        if filter_idx is None:
            # There was no filter to begin with
            pass
        elif entry_idx is None:
            # There was no entry to begin with
            pass
        elif len(entries) == 1:
            # There is only one entry, remove filter
            mso.existing = {}
            ops.append(dict(op="remove", path=filter_path))

        else:
            mso.existing = {}
            ops.append(dict(op="remove", path=entry_path))

    elif state == "present":
        if not mso.existing:
            if display_name is None:
                display_name = entry
            if ethertype is None:
                ethertype = "unspecified"
            if ip_protocol is None:
                ip_protocol = "unspecified"
            if tcp_session_rules is None:
                tcp_session_rules = ["unspecified"]
            if source_from is None:
                source_from = "unspecified"
            if source_to is None:
                source_to = "unspecified"
            if destination_from is None:
                destination_from = "unspecified"
            if destination_to is None:
                destination_to = "unspecified"
            if arp_flag is None:
                arp_flag = "unspecified"
            if stateful is None:
                stateful = False
            if fragments_only is None:
                fragments_only = False

        payload = dict(
            name=entry,
            displayName=display_name,
            description=filter_entry_description,
            etherType=ethertype,
            ipProtocol=ip_protocol,
            tcpSessionRules=tcp_session_rules,
            sourceFrom=source_from,
            sourceTo=source_to,
            destinationFrom=destination_from,
            destinationTo=destination_to,
            arpFlag=arp_flag,
            stateful=stateful,
            matchOnlyFragments=fragments_only,
        )

        mso.sanitize(payload, collate=True)

        if filter_idx is None:
            # Filter does not exist, so we have to create it
            if filter_display_name is None:
                filter_display_name = filter_name

            payload = dict(
                name=filter_name,
                displayName=filter_display_name,
                description=filter_description,
                entries=[mso.sent],
            )

            ops.append(dict(op="add", path=filters_path + "/-", value=payload))

        elif entry_idx is None:
            # Entry does not exist, so we have to add it
            ops.append(dict(op="add", path=entries_path + "/-", value=mso.sent))

        else:
            # Entry exists, we have to update it
            for key, value in mso.sent.items():
                ops.append(dict(op="replace", path=entry_path + "/" + key, value=value))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
