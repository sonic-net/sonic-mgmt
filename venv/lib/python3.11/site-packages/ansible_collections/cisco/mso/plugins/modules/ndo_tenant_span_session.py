#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Samita Bhattacharjee (@samiib) <samitab@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: ndo_tenant_span_session
version_added: "2.11.0"
short_description: Manage Tenant SPAN Sessions on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Switched Port Analyzer (SPAN) Sessions on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Samita Bhattacharjee (@samiib)
options:
  template:
    description:
    - The name of the template.
    - The template must be a Tenant Monitoring Policy template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the template.
    - The template must be a Tenant Monitoring Policy template.
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
  sources:
    description:
    - The SPAN Session sources.
    - Providing a new list of O(sources) will replace the existing sources from the SPAN Session.
    - Providing an empty list will remove the O(sources=[]) from the SPAN Session.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the SPAN Session source.
        type: str
        required: true
      direction:
        description:
        - The direction of the SPAN Session source.
        type: str
        required: true
        choices: [ incoming, outgoing, both ]
      epg_uuid:
        description:
        - The UUID of the source Endpoint Group (EPG) to use for the SPAN Session.
        - This parameter or O(sources.epg) is required.
        type: str
      epg:
        description:
        - The EPG to use for the SPAN Session source.
        - This parameter or O(sources.epg_uuid) is required.
        type: dict
        suboptions:
          name:
            description:
            - The name of the source EPG.
            type: str
            required: true
          template:
            description:
            - The name of the template that contains the source EPG.
            - This parameter or O(sources.epg.template_id) is required.
            type: str
          template_id:
            description:
            - The ID of the template that contains the source EPG.
            - This parameter or O(sources.epg.template) is required.
            type: str
          schema_id:
            description:
            - The ID of the schema that contains the source EPG.
            - This parameter or O(sources.epg.schema) is required.
            type: str
          schema:
            description:
            - The name of the schema that contains the source EPG.
            - This parameter or O(sources.epg.schema_id) is required.
            type: str
          anp:
            description:
            - The name of the Application Profile (ANP) that contains the source EPG.
            - This parameter or O(sources.epg.anp_uuid) is required.
            type: str
          anp_uuid:
            description:
            - The UUID of the ANP that contains the source EPG.
            - This parameter or O(sources.epg.anp) is required.
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
    type: dict
    suboptions:
      epg_uuid:
        description:
        - The UUID of the destination EPG to use for the SPAN Session.
        - This parameter or O(destination_epg.epg) is required when creating the SPAN Session.
        type: str
      epg:
        description:
        - The destination EPG to use for the SPAN Session.
        - This parameter or O(destination_epg.epg_uuid) is required when creating the SPAN Session.
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
            - The ID of the  that contains the destination EPG.
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
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template), O(destination_epg.epg) and O(sources.epg) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Tenant Monitoring Policy template.
  Use M(cisco.mso.mso_schema_template_anp_epg) to create the EPGs.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.mso_schema_template_anp_epg
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new SPAN Session
  cisco.mso.ndo_tenant_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: monitoring_tenant_template
    name: span_session_1
    sources:
      - name: source_1
        epg_uuid: '{{ query_epg_1.current.uuid }}'
        direction: both
      - name: source_2
        direction: outgoing
        epg:
          name: epg_2
          anp: anp_1
          template: template_1
          schema: schema_1
    admin_state: enabled
    mtu: 9216
    destination_epg:
      epg:
        name: epg_3
        anp: anp_1
        template: template_1
        schema: schema_1
      destination_ip: 10.1.1.1
      source_ip_prefix: 10.1.1.1/24
      span_version: v1
      enforce_span_version: false
      flow_id: 15
      ttl: 128
      dscp: af11
    state: present
  register: create_span_session_1

- name: Update the name of the SPAN Session using UUID
  cisco.mso.ndo_tenant_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: "{{ create_monitoring_tenant.current.templateId }}"
    uuid: "{{ create_span_session_1.current.uuid }}"
    name: span_session_1_updated
    state: present
  register: update_span_session_1

- name: Query an existing SPAN Session using UUID
  cisco.mso.ndo_tenant_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: monitoring_tenant_template
    uuid: "{{ create_span_session_1.current.uuid }}"
    state: query
  register: query_with_uuid

- name: Query an existing SPAN Session using name
  cisco.mso.ndo_tenant_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: monitoring_tenant_template
    name: span_session_1_updated
    state: query
  register: query_with_name

- name: Query all SPAN Sessions
  cisco.mso.ndo_tenant_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: monitoring_tenant_template
    state: query
  register: query_all

- name: Remove all sources from a SPAN Session
  cisco.mso.ndo_tenant_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: monitoring_tenant_template
    name: span_session_1_updated
    sources: []
    state: present

- name: Delete an existing SPAN Session using UUID
  cisco.mso.ndo_tenant_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: monitoring_tenant_template
    uuid: "{{ create_span_session_1.current.uuid }}"
    state: absent

- name: Delete an existing SPAN Session using Name
  cisco.mso.ndo_tenant_span_session:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: monitoring_tenant_template
    name: span_session_1_updated
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, epg_object_reference_spec
from ansible_collections.cisco.mso.plugins.module_utils.schemas import MSOSchemas
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
        sources=dict(
            type="list",
            elements="dict",
            mutually_exclusive=[
                ("epg", "epg_uuid"),
            ],
            required_one_of=[
                ["epg", "epg_uuid"],
            ],
            options=dict(
                name=dict(type="str", required=True),
                direction=dict(type="str", required=True, choices=["incoming", "outgoing", "both"]),
                epg_uuid=dict(type="str"),
                epg=epg_object_reference_spec(),
            ),
        ),
        admin_state=dict(type="str", choices=list(ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP)),
        mtu=dict(type="int"),
        destination_epg=dict(
            type="dict",
            mutually_exclusive=[
                ("epg", "epg_uuid"),
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
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("template", "template_id"),
        ],
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
        required_one_of=[["template", "template_id"]],
    )

    mso = MSOModule(module)
    mso_schemas = MSOSchemas(mso)

    template_name = module.params.get("template")
    template_id = module.params.get("template_id")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    sources = module.params.get("sources")
    admin_state = module.params.get("admin_state")
    mtu = module.params.get("mtu")
    destination_epg = module.params.get("destination_epg")
    state = module.params.get("state")

    ops = []
    match = None
    reference_collection = {
        "epgRef": {
            "name": "epgName",
            "reference": "epgRef",
            "type": "epg",
            "template": "epgTemplateName",
            "templateId": "epgTemplateId",
            "schema": "epgSchemaName",
            "schemaId": "epgSchemaId",
        },
        "epg": {
            "name": "epgName",
            "reference": "epg",
            "type": "epg",
            "template": "epgTemplateName",
            "templateId": "epgTemplateId",
            "schema": "epgSchemaName",
            "schemaId": "epgSchemaId",
        },
    }

    mso_template = MSOTemplate(mso, "monitoring_tenant", template_name, template_id)
    mso_template.validate_template("monitoring")
    object_description = "SPAN Session"
    path = "/monitoringTemplate/template/spanSessions"
    span_session_path = None

    existing_span_sessions = mso_template.template.get("monitoringTemplate", {}).get("template", {}).get("spanSessions") or []

    if name or uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_span_sessions,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            span_session_path = "{0}/{1}".format(path, match.index)
            mso_template.update_config_with_template_and_references(match.details, reference_collection)
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = [mso_template.update_config_with_template_and_references(obj, reference_collection) for obj in existing_span_sessions]

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        mso_values = dict(name=name, description=description, destination=dict(mtu=mtu))
        if admin_state is not None or sources is not None:
            source_group = dict()
            if admin_state is not None:
                source_group["enableAdminState"] = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(admin_state)
            if sources is not None:
                source_group["sources"] = format_sources(mso_schemas, sources)
            mso_values["sourceGroup"] = source_group
        if destination_epg:
            mso_values["destination"]["remote"] = dict(
                epgRef=mso_schemas.get_epg_uuid(destination_epg.get("epg"), destination_epg.get("epg_uuid")),
                spanVersion=destination_epg.get("span_version"),
                enforceSpanVersion=destination_epg.get("enforce_span_version"),
                destIPAddress=destination_epg.get("destination_ip"),
                srcIPPrefix=destination_epg.get("source_ip_prefix"),
                flowID=destination_epg.get("flow_id"),
                ttl=destination_epg.get("ttl"),
                dscp=TARGET_DSCP_MAP.get(destination_epg.get("dscp")),
            )

        if match:
            mso_update_values = {
                "name": name,
                "description": description,
                ("destination", "mtu"): mtu,
            }
            source_group = mso_values.get("sourceGroup")
            if source_group:
                mso_update_values[("sourceGroup", "enableAdminState")] = source_group.get("enableAdminState")
                mso_update_values[("sourceGroup", "sources")] = source_group.get("sources")
            if destination_epg:
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

            proposed_payload = copy.deepcopy(match.details)
            append_update_ops_data(ops, proposed_payload, span_session_path, mso_update_values)
            mso.sanitize(proposed_payload, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="{0}/-".format(path), value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=span_session_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        node_profiles = response.get("monitoringTemplate", {}).get("template", {}).get("spanSessions") or []
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            node_profiles,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            mso_template.update_config_with_template_and_references(match.details, reference_collection)
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso_template.update_config_with_template_and_references(mso.proposed, reference_collection)
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def format_sources(schemas, sources):
    source_list = []
    for source in sources:
        source_values = {
            "name": source.get("name"),
            "direction": source.get("direction"),
            "epg": schemas.get_epg_uuid(source.get("epg"), source.get("epg_uuid")),
        }
        source_list.append(source_values)
    return source_list


if __name__ == "__main__":
    main()
