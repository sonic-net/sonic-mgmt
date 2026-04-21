#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_fabric_span_session
version_added: "2.11.0"
short_description: Manage Fabric SPAN Sessions on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Switched Port Analyzer (SPAN) Sessions on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.4) and later.
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
  name:
    description:
    - The name of the SPAN Session.
    type: str
    aliases: [ span_session ]
  uuid:
    description:
    - The UUID of the SPAN Session.
    - This parameter is required when the O(name) needs to be updated.
    type: str
    aliases: [ span_session_uuid ]
  description:
    description:
    - The description of the SPAN Session.
    type: str
  admin_state:
    description:
    - The administrative state of the SPAN Session.
    - Defaults to C(enabled) when unset during creation.
    choices: [ enabled, disabled ]
    type: str
  mtu:
    description:
    - The MTU truncation size for the SPAN packets.
    - The value must be in the range 64 - 9216.
    - Defaults to 1518 when unset during creation.
    type: int
  destination_epg:
    description:
    - The destination EPG configuration group.
    - This parameter or O(destination_port) or O(destination_port_channel) is required when creating the SPAN Session.
    type: dict
    suboptions:
      epg_uuid:
        description:
        - The UUID of the destination EPG to use for the SPAN Session.
        - This parameter or O(destination_epg.epg) is required.
        type: str
      epg:
        description:
        - The destination EPG to use for the SPAN Session.
        - This parameter or O(destination_epg.epg_uuid) is required.
        type: dict
        suboptions:
          name:
            description:
            - The name of the destination EPG.
            type: str
            required: true
          template:
            description:
            - The name of the template that contains the destination EPG.
            - This parameter or O(destination_epg.epg.template_id) is required.
            type: str
          template_id:
            description:
            - The ID of the template that contains the destination EPG.
            - This parameter or O(destination_epg.epg.template) is required.
            type: str
          schema_id:
            description:
            - The ID of the schema that contains the destination EPG.
            - This parameter or O(destination_epg.epg.schema) is required.
            type: str
          schema:
            description:
            - The name of the schema that contains the destination EPG.
            - This parameter or O(destination_epg.epg.schema_id) is required.
            type: str
          anp:
            description:
            - The name of the ANP that contains the destination EPG.
            - This parameter or O(destination_epg.epg.anp_uuid) is required.
            type: str
          anp_uuid:
            description:
            - The UUID of the ANP that contains the destination EPG.
            - This parameter or O(destination_epg.epg.anp) is required.
            type: str
      destination_ip:
        description:
        - The destination IP address to route SPAN Session packets.
        type: str
      source_ip_prefix:
        description:
        - The prefix used to assign source IP addresses to ERSPAN packets which can be used to identify which Leaf or Spine is sending the traffic.
        - This can be any IP. If the prefix is used, the node ID of the source node is used for the undefined bits of the prefix.
        type: str
      span_version:
        description:
        - The version of the SPAN Session.
        - Defaults to C(v2) when unset during creation.
        choices: [ v1, v2 ]
        type: str
      enforce_span_version:
        description:
        - Enforce the SPAN Session version defined in O(destination_epg.span_version).
        - Defaults to true when unset during creation.
        type: bool
      flow_id:
        description:
        - The flow ID of the SPAN Session packets.
        - The value must be in the range 1 - 1023.
        - Defaults to 1 when unset during creation.
        type: int
      ttl:
        description:
        - The time to live (TTL) of the SPAN Session packets.
        - The value must be in the range 1 - 1023.
        - Defaults to 1 when unset during creation.
        type: int
      dscp:
        description:
        - The DSCP value for sending the monitored SPAN Session packets.
        - Defaults to C(unspecified) when unset during creation.
        choices:
          - af11
          - af12
          - af13
          - af21
          - af22
          - af23
          - af31
          - af32
          - af33
          - af41
          - af42
          - af43
          - cs0
          - cs1
          - cs2
          - cs3
          - cs4
          - cs5
          - cs6
          - cs7
          - expedited_forwarding
          - voice_admit
          - unspecified
        type: str
  destination_port:
    description:
    - The destination port configuration group.
    - This parameter or O(destination_epg) or O(destination_port_channel) is required when creating the SPAN Session.
    type: dict
    suboptions:
      port_uuid:
        description:
        - The UUID of the destination port to use for the SPAN Session.
        - This parameter or O(destination_port.port) is required.
        type: str
      port:
        description:
        - The destination port to use for the SPAN Session.
        - This parameter or O(destination_port.port_uuid) is required.
        type: dict
        suboptions:
          node:
            description:
            - The Node ID of the Node to use for the SPAN Session.
            type: int
            required: true
          interface:
            description:
            - The Ethernet interface of the Node to use for the SPAN Session
            type: str
            required: true
  destination_port_channel:
    description:
    - The destination port channel configuration group.
    - This parameter or O(destination_epg) or O(destination_port) is required when creating the SPAN Session.
    type: dict
    suboptions:
      port_channel_uuid:
        description:
        - The UUID of the destination port channel to use for the SPAN Session.
        - This parameter or O(destination_port_channel.port_channel) is required.
        type: str
      port_channel:
        description:
        - The destination port channel to use for the SPAN Session.
        - This parameter or O(destination_port_channel.port_channel_uuid) is required.
        type: dict
        suboptions:
          name:
            description:
            - The name of the destination port channel.
            type: str
            required: true
          template:
            description:
            - The name of the template that contains the destination port channel.
            - This parameter or O(destination_port_channel.port_channel.template_id) is required.
            type: str
          template_id:
            description:
            - The ID of the template that contains the destination port channel.
            - This parameter or O(destination_port_channel.port_channel.template) is required.
            type: str
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Fabric Monitoring Access Policy template.
- The O(destination_epg.epg) must exist before using it with this module in your playbook.
  Use M(cisco.mso.mso_schema_template_anp_epg) to create the EPG.
- The O(destination_port_channel.port_channel) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_port_channel_interface) to create the Fabric resource port channel interface.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.mso_schema_template_anp_epg
- module: cisco.mso.ndo_port_channel_interface
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create Fabric SPAN Session with destination EPG
  cisco.mso.ndo_fabric_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_test_epg
    destination_epg:
      epg:
        schema: ansible_test
        template: Template1
        anp: Anp1
        name: EPG1
      destination_ip: "1.1.1.1"
      source_ip_prefix: "2.2.2.2"
    state: present
  register: create_epg_span_session

- name: Create Fabric SPAN Session with destination Port
  cisco.mso.ndo_fabric_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_test_port
    destination_port:
      port:
        node: 101
        interface: "eth1/1"
    state: present

- name: Create Fabric SPAN Session with destination Port Channel
  cisco.mso.ndo_fabric_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_test_pc
    destination_port_channel:
      port_channel:
        template: ansible_test
        name: ansible_test_resource_pc_1
    state: present

- name: Update Fabric SPAN Session from destination EPG to destination Port
  cisco.mso.ndo_fabric_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_test_epg
    destination_port:
      port:
        node: 101
        interface: "eth1/1"
    state: present

- name: Update Fabric SPAN Session from destination Port to destination Port Channel
  cisco.mso.ndo_fabric_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_test_port
    destination_port_channel:
      port_channel:
        template: ansible_test
        name: ansible_test_resource_pc_1
    state: present

- name: Update Fabric SPAN Session from destination Port Channel to destination EPG
  cisco.mso.ndo_fabric_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_test_pc
    destination_epg:
      epg:
        schema: ansible_test
        template: Template1
        anp: Anp1
        name: EPG1
      destination_ip: "1.1.1.1"
      source_ip_prefix: "2.2.2.2"
    state: present

- name: Update the Fabric SPAN Session name using UUID
  cisco.mso.ndo_fabric_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    uuid: "{{ create_epg_span_session.current.uuid }}"
    name: ansible_test_pc_updated
    state: present

- name: Query a specific Fabric SPAN Session using name
  cisco.mso.ndo_fabric_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_test_pc_updated
    state: query
  register: query_with_name

- name: Query a specific Fabric SPAN Session using UUID
  cisco.mso.ndo_fabric_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    uuid: "{{ create_epg_span_session.current.uuid }}"
    state: query
  register: query_with_uuid

- name: Query all Fabric SPAN Sessions
  cisco.mso.ndo_fabric_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    state: query
  register: query_all_objects

- name: Delete a specific Fabric SPAN Session using Name
  cisco.mso.ndo_fabric_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_test_pc_updated
    state: absent

- name: Delete a Fabric SPAN Session using UUID
  cisco.mso.ndo_fabric_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: ansible_test
    uuid: "{{ create_epg_span_session.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, epg_object_reference_spec
from ansible_collections.cisco.mso.plugins.module_utils.schemas import MSOSchemas
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import TARGET_DSCP_MAP, ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        name=dict(type="str", aliases=["span_session"]),
        uuid=dict(type="str", aliases=["span_session_uuid"]),
        description=dict(type="str"),
        admin_state=dict(type="str", choices=["enabled", "disabled"]),
        mtu=dict(type="int"),
        destination_epg=dict(
            type="dict",
            mutually_exclusive=[
                ("epg", "epg_uuid"),
            ],
            required_one_of=[
                ["epg", "epg_uuid"],
            ],
            options=dict(
                epg_uuid=dict(type="str"),
                epg=epg_object_reference_spec(),
                destination_ip=dict(type="str"),
                source_ip_prefix=dict(type="str"),
                span_version=dict(type="str", choices=["v1", "v2"]),
                enforce_span_version=dict(type="bool"),
                flow_id=dict(type="int"),
                ttl=dict(type="int"),
                dscp=dict(type="str", choices=list(TARGET_DSCP_MAP)),
            ),
        ),
        destination_port=dict(
            type="dict",
            mutually_exclusive=[
                ("port", "port_uuid"),
            ],
            required_one_of=[
                ["port", "port_uuid"],
            ],
            options=dict(
                port_uuid=dict(type="str"),
                port=dict(
                    type="dict",
                    options=dict(
                        node=dict(type="int", required=True),
                        interface=dict(type="str", required=True),
                    ),
                ),
            ),
        ),
        destination_port_channel=dict(
            type="dict",
            mutually_exclusive=[
                ("port_channel", "port_channel_uuid"),
            ],
            required_one_of=[
                ["port_channel", "port_channel_uuid"],
            ],
            options=dict(
                port_channel_uuid=dict(type="str"),
                port_channel=dict(
                    type="dict",
                    options=dict(
                        name=dict(type="str", required=True),
                        template=dict(type="str"),
                        template_id=dict(type="str"),
                    ),
                    required_one_of=[
                        ["template", "template_id"],
                    ],
                    mutually_exclusive=[
                        ("template", "template_id"),
                    ],
                ),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[("template", "template_id"), ("destination_epg", "destination_port_channel", "destination_port")],
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
        required_one_of=[
            ["template", "template_id"],
        ],
    )

    mso = MSOModule(module)
    mso_schemas = MSOSchemas(mso)
    mso_templates = MSOTemplates(mso)

    template_name = module.params.get("template")
    template_id = module.params.get("template_id")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    admin_state = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(module.params.get("admin_state")) if module.params.get("admin_state") else None
    mtu = module.params.get("mtu")
    destination_epg = module.params.get("destination_epg")
    destination_port = module.params.get("destination_port")
    destination_port_channel = module.params.get("destination_port_channel")
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "monitoring_tenant", template_name, template_id)
    mso_template.validate_template("monitoring")
    object_description = "SPAN Session"
    site_id = mso_template.template.get("monitoringTemplate").get("sites")[0].get("siteId")

    match = None
    if uuid or name:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            mso_template.template.get("monitoringTemplate", {}).get("template", {}).get("spanSessions", []),
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
    else:
        match = mso_template.template.get("monitoringTemplate", {}).get("template", {}).get("spanSessions", [])

    if (uuid or name) and match:
        set_fabric_span_session_object_details(mso_template, site_id, match.details)
        mso.existing = mso.previous = copy.deepcopy(match.details)  # Query a specific object
    elif match:
        mso.existing = [set_fabric_span_session_object_details(mso_template, site_id, obj) for obj in match]  # Query all objects

    if state != "query":
        span_session_path = "/monitoringTemplate/template/spanSessions/{0}".format(match.index if match else "-")

    ops = []

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        mso_values = dict()
        if destination_epg:
            mso_values["destination"] = dict(
                remote=dict(
                    epgRef=mso_schemas.get_epg_uuid(destination_epg.get("epg"), destination_epg.get("epg_uuid")),
                    spanVersion=destination_epg.get("span_version"),
                    enforceSpanVersion=destination_epg.get("enforce_span_version"),
                    destIPAddress=destination_epg.get("destination_ip"),
                    srcIPPrefix=destination_epg.get("source_ip_prefix"),
                    flowID=destination_epg.get("flow_id"),
                    ttl=destination_epg.get("ttl"),
                    dscp=TARGET_DSCP_MAP.get(destination_epg.get("dscp")),
                ),
                mtu=mtu,
            )

        if destination_port:
            # Destination Port supports UUIDs, but we have no module to get them
            destination_port_uuid = destination_port.get("port_uuid")

            if destination_port_uuid is None:
                node = destination_port.get("port").get("node")
                interface_port = destination_port.get("port").get("interface")
                destination_port_uuid = mso.get_site_interface_details(site_id=site_id, uuid=None, node=node, port=interface_port).get("uuid")
            mso_values["destination"] = dict(local=dict(accessInterface=destination_port_uuid), mtu=mtu)

        if destination_port_channel:
            destination_port_channel_uuid = destination_port_channel.get("port_channel_uuid")
            if destination_port_channel_uuid is None:
                fabric_resource_template = mso_templates.get_template(
                    "fabric_resource",
                    destination_port_channel.get("port_channel").get("template"),
                    destination_port_channel.get("port_channel").get("template_id"),
                )

                destination_port_channel_uuid = fabric_resource_template.get_template_policy_uuid(
                    "fabric_resource", destination_port_channel.get("port_channel").get("name"), "portChannels"
                )

            mso_values["destination"] = dict(local=dict(portChannel=destination_port_channel_uuid), mtu=mtu)

        if match:
            mso_update_values = {"name": name, "description": description}
            mso_update_values[("destination", "mtu")] = mtu

            if admin_state is not None:
                mso_update_values[("sourceGroup", "enableAdminState")] = admin_state

            if destination_epg:
                if match.details.get("destination", {}).get("local", {}).get("accessInterface") or match.details.get("destination", {}).get("local", {}).get(
                    "portChannel"
                ):
                    mso_update_values[("destination", "local")] = dict()

                remote_group = mso_values.get("destination", {}).get("remote")
                if remote_group:
                    mso_update_values[("destination", "remote", "epgRef")] = remote_group.get("epgRef")
                    mso_update_values[("destination", "remote", "spanVersion")] = remote_group.get("spanVersion")
                    mso_update_values[("destination", "remote", "enforceSpanVersion")] = remote_group.get("enforceSpanVersion")
                    mso_update_values[("destination", "remote", "destIPAddress")] = remote_group.get("destIPAddress")
                    mso_update_values[("destination", "remote", "srcIPPrefix")] = remote_group.get("srcIPPrefix")
                    mso_update_values[("destination", "remote", "flowID")] = remote_group.get("flowID")
                    mso_update_values[("destination", "remote", "ttl")] = remote_group.get("ttl")
                    mso_update_values[("destination", "remote", "dscp")] = remote_group.get("dscp")

            if destination_port:
                if match.details.get("destination", {}).get("remote", {}).get("epgRef"):
                    mso_update_values[("destination", "remote")] = dict()

                if match.details.get("destination", {}).get("local", {}).get("portChannel"):
                    mso_update_values[("destination", "local")] = dict()

                mso_update_values[("destination", "local")] = dict(accessInterface=destination_port_uuid)

            if destination_port_channel:
                if match.details.get("destination", {}).get("remote", {}).get("epgRef"):
                    mso_update_values[("destination", "remote")] = dict()

                if match.details.get("destination", {}).get("local", {}).get("accessInterface"):
                    mso_update_values[("destination", "local")] = dict()

                mso_update_values[("destination", "local")] = dict(portChannel=destination_port_channel_uuid)

            proposed_payload = copy.deepcopy(match.details)
            append_update_ops_data(ops, proposed_payload, span_session_path, mso_update_values)
            mso.sanitize(proposed_payload, collate=True)
        else:
            mso_values["name"] = name
            mso_values["description"] = description

            if admin_state is not None:
                mso_values["sourceGroup"] = dict(enableAdminState=admin_state)

            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=span_session_path, value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=span_session_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            response.get("monitoringTemplate", {}).get("template", {}).get("spanSessions", []),
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            set_fabric_span_session_object_details(mso_template, site_id, match.details)
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        set_fabric_span_session_object_details(mso_template, site_id, mso.proposed)
        mso.existing = mso.proposed if state == "present" else {}
    mso.exit_json()


def set_fabric_span_session_object_details(mso_template, site_id, span_session):
    if span_session:
        span_session.update({"templateId": mso_template.template_id, "templateName": mso_template.template_name})
        if span_session.get("destination", {}).get("local", {}).get("accessInterface"):
            interface = mso_template.mso.get_site_interface_details(site_id, span_session.get("destination").get("local").get("accessInterface"))
            interface.pop("uuid", None)
            span_session.get("destination").get("local").update(interface)
        else:
            reference_details = {
                "remote": {
                    "name": "epgName",
                    "reference": "epgRef",
                    "type": "epg",
                    "template": "epgTemplateName",
                    "templateId": "epgTemplateId",
                    "schema": "epgSchemaName",
                    "schemaId": "epgSchemaId",
                },
                "local": {
                    "name": "portChannelName",
                    "reference": "portChannel",
                    "type": "portChannel",
                    "template": "portChannelTemplateName",
                    "templateId": "portChannelTemplateId",
                },
            }
            mso_template.update_config_with_template_and_references(
                span_session.get("destination"),
                reference_details,
                False,
            )
    return span_session


if __name__ == "__main__":
    main()
