#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_fabric_span_session_source
version_added: "2.11.0"
short_description: Manage Fabric SPAN Sessions Source on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Switched Port Analyzer (SPAN) Sessions Source on Cisco Nexus Dashboard Orchestrator (NDO).
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
  name:
    description:
    - The name of the SPAN Session source.
    type: str
  direction:
    description:
    - The direction of the SPAN Session source.
    - Defaults to O(direction=incoming) when unset during creation.
    type: str
    choices: [ incoming, outgoing, both ]
  span_drop_packets:
    description:
    - The SPAN Drop Packets of the SPAN Session source.
    - SPAN Drop Packets are packets that get dropped when the SPAN destination port cannot handle the volume of mirrored traffic from the source ports.
    - Defaults to O(span_drop_packets=false) when unset during creation.
    - The O(filter_epg) and O(filter_l3out) are not configurable when O(span_drop_packets=true).
    type: bool
  filter_epg:
    description:
    - The Filter EPG of the SPAN Session source.
    - When the Filter EPG is specified in the configuration, the Filter L3Out will be removed.
    - This parameter and O(filter_l3out) are mutually exclusive.
    - Providing an empty dictionary O(filter_epg={}) will remove the filter l3out from the SPAN Session source.
    type: dict
    aliases: [ epg ]
    suboptions:
      uuid:
        description:
        - The UUID of the EPG used to configure the Filter EPG.
        - This parameter or O(filter_epg.reference) is required.
        type: str
        aliases: [ epg_uuid ]
      reference:
        description:
        - The EPG object detail used to configure the Filter EPG.
        - This parameter or O(filter_epg.uuid) is required.
        type: dict
        aliases: [ ref ]
        suboptions:
          name:
            description:
            - The name of the EPG.
            type: str
            required: true
          template:
            description:
            - The name of the template that contains the EPG.
            - This parameter or O(filter_epg.reference.template_id) is required.
            type: str
          template_id:
            description:
            - The ID of the template that contains the EPG.
            - This parameter or O(filter_epg.reference.template) is required.
            type: str
          schema_id:
            description:
            - The ID of the schema that contains the EPG.
            - This parameter or O(filter_epg.reference.schema) is required.
            type: str
          schema:
            description:
            - The name of the schema that contains the EPG.
            - This parameter or O(filter_epg.reference.schema_id) is required.
            type: str
          anp:
            description:
            - The name of the ANP that contains the EPG.
            - This parameter or O(filter_epg.reference.anp_uuid) is required.
            type: str
          anp_uuid:
            description:
            - The UUID of the ANP that contains the EPG.
            - This parameter or O(filter_epg.reference.anp) is required.
            type: str
  filter_l3out:
    description:
    - The Filter L3Out of the SPAN Session source.
    - When the Filter L3Out is specified in the configuration, the Filter EPG will be removed.
    - This parameter and O(filter_epg) are mutually exclusive.
    - The L3Out must be defined in either the L3Out template or directly within the APIC tenant.
    - The Filter L3Out for a SPAN Session source does not support using an L3Out from an application tenant template.
    - Providing an empty dictionary O(filter_l3out={}) will remove the filter l3out from the SPAN Session source.
    type: dict
    aliases: [ l3out ]
    suboptions:
      reference:
        description:
        - The Filter L3Out object detail used to configure the Filter L3Out.
        - This parameter or O(filter_l3out.uuid) is required.
        type: dict
        aliases: [ ref ]
        suboptions:
          name:
            description:
            - The name of the L3Out.
            required: true
            type: str
          tenant:
            description:
            - The name of the tenant. This parameter is used to associate the L3Out from APIC.
            - This parameter or O(filter_l3out.reference.template), or O(filter_l3out.reference.template_id) is required.
            type: str
          template:
            description:
            - The name of the L3Out template.
            - This parameter or O(filter_l3out.reference.template_id), or O(filter_l3out.reference.tenant) is required.
            type: str
          template_id:
            description:
            - The ID of the L3Out template.
            - This parameter or O(filter_l3out.reference.template), or O(filter_l3out.reference.tenant) is required.
            type: str
      uuid:
        description:
        - The UUID of the L3Out.
        - This parameter or O(filter_l3out.reference) is required.
        type: str
        aliases: [ l3out_uuid ]
      vlan_id:
        description:
        - The ID of the VLAN, which is associated with L3Out interface.
        - This parameter is required to configure the Filter L3Out.
        type: int
  access_paths:
    description:
    - The Access Path of the SPAN Session source.
    - Providing a new list of O(access_paths) will completely replace an existing one from the SPAN Session source.
    - Providing an empty list will remove the O(access_paths=[]) from the SPAN Session source.
    type: list
    elements: dict
    suboptions:
      access_path_type:
        description:
        - The type of the Access Path.
        type: str
        choices: [ port, port_channel, virtual_port_channel, vpc_component_pc ]
        aliases: [ type ]
      uuid:
        description:
        - The UUID of the 'Access Port' or 'Port Channel', or 'Virtual Port Channel' which is used to create the Access Path.
        type: str
      node:
        description:
        - The ID of the Node. This parameter is required when O(access_paths.access_path_type=port) or O(access_paths.access_path_type=vpc_component_pc).
        type: int
      interface:
        description:
        - The interface of the Node. This parameter is required to configure the O(access_paths.access_path_type=port).
        type: str
      name:
        description:
        - The name of the 'Port Channel' or 'Virtual Port Channel' which is used to create the Access Path.
        type: str
      template:
        description:
        - The name of the Fabric Resource Policy template.
        - This parameter or O(access_paths.template_id) is required when O(access_paths.access_path_type=port_channel),
          O(access_paths.access_path_type=virtual_port_channel), or O(access_paths.access_path_type=vpc_component_pc).
        type: str
      template_id:
        description:
        - The ID of the Fabric Resource Policy template.
        - This parameter or O(access_paths.template) is required when O(access_paths.access_path_type=port_channel),
          O(access_paths.access_path_type=virtual_port_channel), or O(access_paths.access_path_type=vpc_component_pc).
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
- The O(span_session_name) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_fabric_span_session) to create the Fabric SPAN Session.
- The O(filter_epg.reference) must exist before using it with this module in your playbook.
  Use M(cisco.mso.mso_schema_template_anp_epg) to create the EPG.
- The O(filter_l3out.reference) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_l3out_template) to create the L3Out.
- The O(access_paths.name) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_port_channel_interface) to create the Fabric resource port channel interface.
- The O(access_paths.name) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_virtual_port_channel_interface) to create the Fabric resource virtual port channel interface.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_fabric_span_session
- module: cisco.mso.mso_schema_template_anp_epg
- module: cisco.mso.ndo_port_channel_interface
- module: cisco.mso.ndo_virtual_port_channel_interface
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create the SPAN Session source with access paths
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_2
    direction: outgoing
    span_drop_packets: true
    access_paths:
      - access_path_type: port
        node: 101
        interface: eth1/6
      - access_path_type: port_channel
        name: ansible_test_pc1
        template: ansible_test_fabric_resource
      - access_path_type: virtual_port_channel
        name: ansible_test_vpc1
        template: ansible_test_fabric_resource
      - access_path_type: vpc_component_pc
        name: ansible_test_vpc1
        template: ansible_test_fabric_resource
        node: 101
    state: present
  register: add_ansible_test_source_2

- name: Create the SPAN Session source with access path and filter EPG
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_3
    direction: outgoing
    access_paths:
      - access_path_type: port
        node: 101
        interface: eth1/6
    filter_epg:
      reference:
        schema: ansible_test_schema
        template: template1
        anp: ansible_test_anp
        name: ansible_test_epg1
    state: present

- name: Create the SPAN Session source with access path and filter L3Out
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_4
    direction: outgoing
    access_paths:
      - access_path_type: port
        node: 101
        interface: eth1/1
    filter_l3out:
      reference:
        name: ansible_test_l3out
        template: ansible_test_l3out_template
      vlan_id: 41
    state: present

- name: Create the SPAN Session source with access paths UUID
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: "{{ add_span_session.current.templateId }}"
    span_session_uuid: "{{ add_span_session.current.uuid }}"
    name: ansible_test_source_1
    access_paths:
      - access_path_type: port
        node: 101
        interface: eth1/1
      - access_path_type: port_channel
        uuid: "{{ add_fabric_pc_1.current.uuid }}"
      - access_path_type: virtual_port_channel
        uuid: "{{ add_fabric_vpc1.current.uuid }}"
      - access_path_type: vpc_component_pc
        uuid: "{{ add_fabric_vpc1.current.uuid }}"
        node: 101
    state: present

- name: Update the SPAN Session source Filter EPG using UUID
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_1
    direction: outgoing
    filter_epg:
      uuid: "{{ add_epg.current.epg }}"
    state: present

- name: Update the SPAN Session source Filter L3Out using UUID
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_1
    direction: outgoing
    access_paths:
      - access_path_type: port_channel
        name: ansible_test_pc1
        template: ansible_test_fabric_resource
    filter_l3out:
      uuid: "{{ add_l3out.current.uuid }}"
      vlan_id: 42
    state: present

- name: Query a specific SPAN Session source
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_1
    state: query
  register: query_one

- name: Query all SPAN Session sources
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    state: query
  register: query_all

- name: Delete the SPAN Session source
  cisco.mso.ndo_fabric_span_session_source:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_mon_pol
    span_session_name: ansible_test_span_session
    name: ansible_test_source_1
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, epg_object_reference_spec
from ansible_collections.cisco.mso.plugins.module_utils.schemas import MSOSchemas
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data, check_if_all_elements_are_none
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        span_session_name=dict(type="str"),
        span_session_uuid=dict(type="str"),
        name=dict(type="str"),
        direction=dict(type="str", choices=["incoming", "outgoing", "both"]),
        span_drop_packets=dict(type="bool"),
        filter_epg=dict(
            type="dict",
            aliases=["epg"],
            options=dict(
                uuid=dict(type="str", aliases=["epg_uuid"]),
                reference=epg_object_reference_spec(aliases=["ref"]),
            ),
            mutually_exclusive=[("reference", "uuid")],
        ),
        filter_l3out=dict(
            type="dict",
            aliases=["l3out"],
            options=dict(
                reference=dict(
                    type="dict",
                    options=dict(
                        name=dict(type="str", required=True),
                        tenant=dict(type="str"),
                        template=dict(type="str"),
                        template_id=dict(type="str"),
                    ),
                    mutually_exclusive=[("tenant", "template", "template_id")],
                    required_one_of=[["tenant", "template", "template_id"]],
                    aliases=["ref"],
                ),
                uuid=dict(type="str", aliases=["l3out_uuid"]),
                vlan_id=dict(type="int"),
            ),
            mutually_exclusive=[("reference", "uuid")],
            required_by={
                "reference": "vlan_id",
                "uuid": "vlan_id",
            },
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
        access_paths=dict(
            type="list",
            elements="dict",
            options=dict(
                uuid=dict(type="str"),
                node=dict(type="int"),
                interface=dict(type="str"),
                name=dict(type="str"),
                template=dict(type="str"),
                template_id=dict(type="str"),
                access_path_type=dict(type="str", choices=["port", "port_channel", "virtual_port_channel", "vpc_component_pc"], aliases=["type"]),
            ),
            mutually_exclusive=[("uuid", "interface", "name"), ("template", "template_id")],
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("template", "template_id"),
            ("span_session_name", "span_session_uuid"),
            ("filter_epg", "filter_l3out"),
        ],
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
        required_one_of=[
            ["template", "template_id"],
            ["span_session_name", "span_session_uuid"],
        ],
    )

    mso = MSOModule(module)
    mso_schemas = MSOSchemas(mso)
    mso_templates = MSOTemplates(mso)

    template_name = module.params.get("template")
    template_id = module.params.get("template_id")
    span_session_name = module.params.get("span_session_name")
    span_session_uuid = module.params.get("span_session_uuid")
    name = module.params.get("name")
    direction = module.params.get("direction")
    span_drop_packets = module.params.get("span_drop_packets")
    filter_epg = module.params.get("filter_epg")
    filter_l3out = module.params.get("filter_l3out")
    access_paths = module.params.get("access_paths")
    state = module.params.get("state")

    if filter_epg is not None and check_if_all_elements_are_none(filter_epg.values()):
        filter_epg = {}

    if filter_l3out is not None and check_if_all_elements_are_none(filter_l3out.values()):
        filter_l3out = {}

    errors = validate_access_paths(access_paths)
    if errors:
        mso.fail_json(msg=", ".join(errors))

    mso_template = MSOTemplate(mso, "monitoring_tenant", template_name, template_id)
    mso_template.validate_template("monitoring")
    site_id = mso_template.template.get("monitoringTemplate").get("sites")[0].get("siteId")

    fabric_span_session = mso_template.get_fabric_span_session(span_session_uuid, span_session_name, fail_module=True)
    match = mso_template.get_fabric_span_session_source(name, fabric_span_session.details.get("sourceGroup", {}).get("sources", []))

    if match and name:
        mso.existing = mso.previous = copy.deepcopy(
            set_fabric_span_session_source_object_details(mso_template, site_id, match.details)
        )  # Query a specific object
    elif match:
        mso.existing = [set_fabric_span_session_source_object_details(mso_template, site_id, obj) for obj in match]  # Query all objects

    if state != "query":
        source_path = "/monitoringTemplate/template/spanSessions/{0}/sourceGroup/sources/{1}".format(fabric_span_session.index, match.index if match else "-")

    ops = []

    if state == "present":
        mso_values = dict(
            name=name,
            direction=direction,
            spanDropPackets=span_drop_packets,
        )

        if filter_epg and (filter_epg.get("reference") or filter_epg.get("uuid")):
            mso_values["epg"] = mso_schemas.get_epg_uuid(filter_epg.get("reference"), filter_epg.get("uuid"))

        if filter_l3out and (filter_l3out.get("reference") or filter_l3out.get("uuid")):
            mso_values["l3out"] = dict(
                encapType="vlan",
                encapValue=filter_l3out.get("vlan_id"),
            )
            if filter_l3out.get("uuid"):
                mso_values["l3out"]["ref"] = filter_l3out.get("uuid")
            elif filter_l3out.get("reference") and filter_l3out.get("reference").get("tenant"):
                mso_values["l3out"]["dn"] = "uni/tn-{0}/out-{1}".format(filter_l3out.get("reference").get("tenant"), filter_l3out.get("reference").get("name"))
            elif filter_l3out.get("reference") and (filter_l3out.get("reference").get("template") or filter_l3out.get("reference").get("template_id")):
                l3out_template = mso_templates.get_template(
                    "l3out", filter_l3out.get("reference").get("template"), filter_l3out.get("reference").get("template_id")
                )
                l3out_match = l3out_template.get_l3out_object(uuid=filter_l3out.get("uuid"), name=filter_l3out.get("reference").get("name"), fail_module=True)
                if l3out_match:
                    mso_values["l3out"]["ref"] = l3out_match.details.get("uuid")

        if access_paths:
            mso_values["accessPaths"] = update_access_paths(mso, site_id, access_paths, mso_templates)

        if match:
            mso_remove_values = []
            proposed_payload = copy.deepcopy(match.details)
            proposed_payload.update({"name": mso_values["name"], "direction": mso_values["direction"], "spanDropPackets": mso_values["spanDropPackets"]})

            if filter_epg == {} and match.details.get("epg"):
                mso_remove_values.append("epg")
                proposed_payload["epg"] = ""
                match.details.pop("epgName")
                match.details.pop("epgTemplateName")
                match.details.pop("epgTemplateId")
                match.details.pop("epgSchemaName")
                match.details.pop("epgSchemaId")
            elif mso_values.get("epg"):
                # When the filter EPG is specified in the configuration, the filter L3Out will be removed.
                # L3Out and EPG cannot be configured simultaneously.
                if match.details.get("l3out"):
                    mso_remove_values.append("l3out")
                proposed_payload["epg"] = mso_values["epg"]

            if filter_l3out == {} and match.details.get("l3out"):
                mso_remove_values.append("l3out")
                proposed_payload["l3out"] = {}
                match.details["l3out"] = {}
            elif mso_values.get("l3out"):
                # When the filter L3Out is specified in the configuration, the filter EPG will be removed.
                # L3Out and EPG cannot be configured simultaneously.
                if match.details.get("epg"):
                    mso_remove_values.append("epg")
                proposed_payload["l3out"] = mso_values["l3out"]

            if access_paths == [] and match.details.get("accessPaths"):
                mso_remove_values.append("accessPaths")
                proposed_payload["accessPaths"] = []
                match.details["accessPaths"] = []
            elif mso_values.get("accessPaths"):
                proposed_payload["accessPaths"] = mso_values["accessPaths"]

            mso.sanitize(proposed_payload, collate=True)
            append_update_ops_data(ops, match.details, source_path, mso_values, mso_remove_values)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=source_path, value=mso.sent))

    elif state == "absent" and match:
        ops.append(dict(op="remove", path=source_path))

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        fabric_span_session = mso_template.get_fabric_span_session(span_session_uuid, span_session_name, fail_module=True)
        match = mso_template.get_fabric_span_session_source(name, fabric_span_session.details.get("sourceGroup", {}).get("sources", []))
        if match:
            mso.existing = set_fabric_span_session_source_object_details(mso_template, site_id, match.details)  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = set_fabric_span_session_source_object_details(mso_template, site_id, mso.proposed) if state == "present" else {}

    mso.exit_json()


def validate_access_paths(access_paths):
    if access_paths:
        errors = []
        for index, path in enumerate(access_paths):
            access_path_type = path.get("access_path_type")
            uuid = path.get("uuid")
            node = path.get("node")
            interface = path.get("interface")
            name = path.get("name")
            template = path.get("template")
            template_id = path.get("template_id")

            # Validate based on access_path_type
            if access_path_type == "port":
                if not uuid and not (node and interface):
                    errors.append(
                        "Access path {0}: when the access_path_type='port', either 'uuid' or both 'node' and 'interface' must be provided.".format(index + 1)
                    )

            elif access_path_type == "port_channel":
                if not uuid and not (name and template) and not (name and template_id):
                    errors.append(
                        (
                            "Access path {0}: when the access_path_type='port_channel', either 'uuid',"
                            + " or both 'name' and 'template', or both 'name' and 'template_id' must be provided."
                        ).format(index + 1)
                    )

            elif access_path_type == "virtual_port_channel":
                if not uuid and not (name and template) and not (name and template_id):
                    errors.append(
                        (
                            "Access path {0}: when the access_path_type 'virtual_port_channel', either 'uuid',"
                            + " or both 'name' and 'template', or both 'name' and 'template_id' must be provided."
                        ).format(index + 1)
                    )

            elif access_path_type == "vpc_component_pc":
                if not (uuid and node) and not (name and template and node) and not (name and template_id and node):
                    errors.append(
                        (
                            "Access path {0}: when the access_path_type 'vpc_component_pc', either both 'uuid' and 'node',"
                            + " or all of 'name', 'template', and 'node',"
                            + " or all of 'name', 'template_id', and 'node' must be provided."
                        ).format(index + 1)
                    )
        return errors


def get_access_path_payload(mso_templates, access_path_config, access_path_type, resource_type):
    uuid = access_path_config.get("uuid")
    if not uuid:
        fabric_template = mso_templates.get_template("fabric_resource", access_path_config.get("template"), access_path_config.get("template_id"))
        uuid = fabric_template.get_template_policy_uuid("fabric_resource", access_path_config.get("name"), resource_type)

    return (
        dict(vpcComponentPc=[dict(vpc=uuid, node=str(access_path_config.get("node")))]) if access_path_type == "vpc_component_pc" else {resource_type: [uuid]}
    )


def update_access_paths(mso, site_id, access_paths, mso_templates):
    updated_paths = []
    for access_path in access_paths:
        if access_path.get("access_path_type") == "port":
            port_uuid = access_path.get("uuid")
            if not port_uuid:
                port_uuid = mso.get_site_interface_details(
                    site_id=site_id,
                    uuid=None,
                    node=access_path.get("node"),
                    port=access_path.get("interface"),
                ).get("uuid")
            updated_paths.append(dict(accessInterfaces=[port_uuid]))

        elif access_path.get("access_path_type") == "port_channel":
            updated_paths.append(get_access_path_payload(mso_templates, access_path, "port_channel", "portChannels"))

        elif access_path.get("access_path_type") == "virtual_port_channel":
            updated_paths.append(get_access_path_payload(mso_templates, access_path, "virtual_port_channel", "virtualPortChannels"))

        elif access_path.get("access_path_type") == "vpc_component_pc":
            updated_paths.append(get_access_path_payload(mso_templates, access_path, "vpc_component_pc", "virtualPortChannels"))

    if len(set([str(path) for path in updated_paths])) == len(updated_paths):
        return updated_paths
    else:
        mso.fail_json(msg="Remove duplicate entries from the access_paths: {0}".format(access_paths))


def set_fabric_span_session_source_object_details(mso_template, site_id, source):
    if source:
        for access_path in source.get("accessPaths", []):  # Adding the object reference name to use the update_config_with_template_and_references function
            if access_path.get("accessInterfaces") and isinstance(access_path.get("accessInterfaces")[0], str):
                access_path.get("accessInterfaces")[0] = mso_template.mso.get_site_interface_details(site_id, access_path.get("accessInterfaces")[0])
            elif access_path.get("portChannels") and isinstance(access_path.get("portChannels")[0], str):
                access_path.get("portChannels")[0] = dict(portChannel=access_path.get("portChannels")[0])
            elif access_path.get("virtualPortChannels") and isinstance(access_path.get("virtualPortChannels")[0], str):
                access_path.get("virtualPortChannels")[0] = dict(virtualPortChannel=access_path.get("virtualPortChannels")[0])

        reference_details = {
            "filterEPG": {
                "name": "epgName",
                "reference": "epg",
                "type": "epg",
                "template": "epgTemplateName",
                "templateId": "epgTemplateId",
                "schema": "epgSchemaName",
                "schemaId": "epgSchemaId",
            },
            "portChannels": {
                "name": "portChannelName",
                "reference": "portChannel",
                "type": "portChannel",
                "template": "portChannelTemplateName",
                "templateId": "portChannelTemplateId",
            },
            "virtualPortChannels": {
                "name": "virtualPortChannelName",
                "reference": "virtualPortChannel",
                "type": "virtualPortChannel",
                "template": "virtualPortChannelTemplateName",
                "templateId": "virtualPortChannelTemplateId",
            },
            "vpcComponentPc": {
                "name": "vpcComponentPcName",
                "reference": "vpc",
                "type": "virtualPortChannel",
                "template": "vpcComponentPcTemplateName",
                "templateId": "vpcComponentPcTemplateId",
            },
            "l3out": {
                "name": "l3outName",
                "reference": "ref",
                "type": "l3out",
                "template": "l3outTemplateName",
                "templateId": "l3outTemplateId",
            },
        }

        mso_template.update_config_with_template_and_references(source, reference_details, True)
    return source


if __name__ == "__main__":
    main()
