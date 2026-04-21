#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_service_device_cluster
version_added: "2.11.0"
short_description: Manage Service Device Clusters on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Service Device Clusters on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is supported on ND v3.2 (NDO v4.4) and later.
author:
- Shreyas Srish (@shrsr)
options:
  template:
    description:
    - The name of the template.
    - The template must be a service device template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the service device template.
    - This parameter or O(template) is required.
    type: str
  uuid:
    description:
    - The UUID of the Service Device Cluster.
    type: str
    aliases: [ service_device_cluster_uuid ]
  name:
    description:
    - The name of the Service Device Cluster.
    type: str
    aliases: [ service_device_cluster ]
  description:
    description:
    - The description of the Service Device Cluster.
    type: str
  device_mode:
    description:
    - Specifies the operational mode of the device.
    type: str
    choices: [ layer1, layer2, layer3 ]
  device_type:
    description:
    - Defines the type of device being configured.
    type: str
    choices: [ firewall, load_balancer, other ]
  interface_properties:
    description:
    - A list containing interface configuration.
    - The old O(interface_properties) will be replaced with the new O(interface_properties) during an update.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the interface.
        type: str
        required: true
      bd:
        description:
        - bd configuration details.
        - This parameter or O(interface_properties.bd_uuid) or O(interface_properties.external_epg_uuid) or O(interface_properties.external_epg) is required.
        type: dict
        suboptions:
          name:
            description:
            - The name associated with the bd.
            type: str
            required: true
          template:
            description:
            - Template associated with the bd.
            - This parameter or O(interface_properties.bd.template_id) is required.
            type: str
          template_id:
            description:
            - ID of the template associated with the bd.
            - This parameter or O(interface_properties.bd.template) is required.
            type: str
          schema:
            description:
            - Schema associated with the bd.
            - This parameter or O(interface_properties.bd.schema_id) is required.
            type: str
          schema_id:
            description:
            - ID of the schema associated with the bd.
            - This parameter or O(interface_properties.bd.schema) is required.
            type: str
      bd_uuid:
        description:
        - UUID of the bd.
        - This parameter or O(interface_properties.bd) or O(interface_properties.external_epg_uuid) or O(interface_properties.external_epg) is required.
        type: str
      external_epg:
        description:
        - external_epg configuration details.
        - This parameter or O(interface_properties.bd) or O(interface_properties.external_epg_uuid) or O(interface_properties.bd_uuid) is required.
        type: dict
        suboptions:
          name:
            description:
            - The name associated with the external_epg.
            type: str
            required: true
          template:
            description:
            - Template associated with the external_epg.
            - This parameter or O(interface_properties.external_epg.template_id) is required.
            type: str
          template_id:
            description:
            - ID of the template associated with the external_epg.
            - This parameter or O(interface_properties.external_epg.template) is required.
            type: str
          schema:
            description:
            - Schema associated with the external_epg.
            - This parameter or O(interface_properties.external_epg.schema_id) is required.
            type: str
          schema_id:
            description:
            - ID of the schema associated with the external_epg.
            - This parameter or O(interface_properties.external_epg.schema) is required.
            type: str
      external_epg_uuid:
        description:
        - UUID of the external_epg.
        - This parameter or O(interface_properties.bd) or O(interface_properties.external_epg) or O(interface_properties.bd_uuid) is required.
        type: str
      ipsla_monitoring_policy:
        description:
        - IPSLA monitoring policy configuration.
        type: dict
        suboptions:
          name:
            description:
            - Name of the IPSLA monitoring policy.
            type: str
          template:
            description:
            - Template for the IPSLA monitoring policy.
            - This parameter or O(interface_properties.ipsla_monitoring_policy.template_id) is required.
            type: str
          template_id:
            description:
            - ID of the template for the IPSLA monitoring policy.
            - This parameter or O(interface_properties.ipsla_monitoring_policy.template) is required.
            type: str
      ipsla_monitoring_policy_uuid:
        description:
        - UUID of the IP SLA monitoring policy.
        type: str
      qos_policy:
        description:
        - Quality of Service (QoS) policy configuration.
        type: dict
        suboptions:
          name:
            description:
            - Name of the QoS policy.
            type: str
          template:
            description:
            - Template for the QoS policy.
            - This parameter or O(interface_properties.qos_policy.template_id) is required.
            type: str
          template_id:
            description:
            - ID of the template for the QoS policy.
            - This parameter or O(interface_properties.qos_policy) is required.
            type: str
      qos_policy_uuid:
        description:
        - UUID of the QoS policy.
        type: str
      preferred_group:
        description:
        - Whether the interface belongs to a preferred group.
        - If this parameter is unspecified, it defaults to False.
        type: bool
      rewrite_source_mac:
        description:
        - Whether to rewrite the source MAC address.
        - If this parameter is unspecified, it defaults to False.
        type: bool
      anycast:
        description:
        - Indicates if anycast is enabled.
        - If this parameter is unspecified, it defaults to False.
        type: bool
      config_static_mac:
        description:
        - Indicates if static MAC configuration is enabled.
        - If this parameter is unspecified, it defaults to False.
        type: bool
        aliases: [ static_mac_configuration ]
      is_backup_redirect_ip:
        description:
        - Indicates if it is a backup redirect IP.
        - If this parameter is unspecified, it defaults to False.
        type: bool
      load_balance_hashing:
        description:
        - Load balancing hashing method.
        - If this parameter is unspecified, it defaults to C(source_destination_and_protocol).
        type: str
        choices: ["source_destination_and_protocol", "source_ip", "destination_ip"]
      pod_aware_redirection:
        description:
        - Indicates if pod-aware redirection is enabled.
        - If this parameter is unspecified, it defaults to False.
        type: bool
      resilient_hashing:
        description:
        - Indicates if resilient hashing is enabled.
        - If this parameter is unspecified, it defaults to False.
        type: bool
      tag_based_sorting:
        description:
        - Indicates if tag-based sorting is enabled.
        - If this parameter is unspecified, it defaults to False.
        type: bool
      min_threshold:
        description:
        - Minimum threshold value for redirect.
        - If this parameter is unspecified, it defaults to 0.
        - This value must be between 0 and 100.
        - This value cannot be greater than or equal to maximum threshold.
        type: int
      max_threshold:
        description:
        - Maximum threshold value for redirect.
        - If this parameter is unspecified, it defaults to 0.
        - This value must be between 0 and 100.
        type: int
      threshold_down_action:
        description:
        - Action to take when the threshold is down.
        type: str
        choices: [ permit, deny, bypass ]
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
  Use M(cisco.mso.ndo_template) to create the service device template.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a service device cluster with one arm
  cisco.mso.ndo_service_device_cluster:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_device_template
    name: device1
    device_mode: layer3
    device_type: firewall
    interface_properties:
      - name: interface1
        external_epg:
          name: ansible_test_epg
          template: ansible_template
          schema: ansible_test
        ipsla_monitoring_policy:
          name: ansible_test_ipsla_monitoring_policy
          template: ansible_tenant_template
        qos_policy:
          name: ansible_custom_qos_policy
          template: ansible_tenant_template
        preferred_group: true
        rewrite_source_mac: false
        config_static_mac: false
        is_backup_redirect_ip: true
        load_balance_hashing: source_ip
        pod_aware_redirection: false
        resilient_hashing: true
        tag_based_sorting: false
        min_threshold: 10
        max_threshold: 100
        threshold_down_action: permit
    state: present
  register: add_device1

- name: Update the service device cluster to advanced
  cisco.mso.ndo_service_device_cluster:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_device_template
    name: device1
    device_mode: layer3
    device_type: firewall
    interface_properties:
      - name: interface1
        external_epg::
          name: ansible_test_epg
          template: ansible_template
          schema: ansible_test
        ipsla_monitoring_policy:
          name: ansible_test_ipsla_monitoring_policy
          template: ansible_tenant_template
        qos_policy:
          name: ansible_custom_qos_policy
          template: ansible_tenant_template
        preferred_group: true
        rewrite_source_mac: false
        config_static_mac: false
        is_backup_redirect_ip: true
        load_balance_hashing: source_ip
        pod_aware_redirection: false
        resilient_hashing: true
        tag_based_sorting: false
        min_threshold: 10
        max_threshold: 100
        threshold_down_action: permit
      - name: interface2
        bd_uuid: '{{ ansible_test_bd_query.current.uuid }}'
        ipsla_monitoring_policy_uuid: '{{ ipsla_monitoring_policy.current.uuid }}'
        qos_policy:
          name: ansible_custom_qos_policy
          template_id: '{{ ansible_test_policy.current.templateId }}'
        preferred_group: true
        rewrite_source_mac: false
        config_static_mac: false
        is_backup_redirect_ip: true
        load_balance_hashing: source_ip
        pod_aware_redirection: false
        resilient_hashing: true
        tag_based_sorting: false
        min_threshold: 10
        max_threshold: 100
        threshold_down_action: permit
      - name: interface3
        bd:
          name: ansible_test_bd
          template: ansible_template
          schema_id: '{{ ansible_test_bd.current.vrfRef.schemaId }}'
        qos_policy:
          name: ansible_custom_qos_policy
          template_id: '{{ ansible_test_policy.current.templateId }}'
        anycast: true
        rewrite_source_mac: false
        config_static_mac: false
        is_backup_redirect_ip: true
        load_balance_hashing: destination_ip
        pod_aware_redirection: false
        resilient_hashing: true
        tag_based_sorting: false
        min_threshold: 10
        max_threshold: 100
        threshold_down_action: deny
    state: present

- name: Query the service device cluster using name
  cisco.mso.ndo_service_device_cluster:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_device_template
    name: device1
    state: query
  register: query_device

- name: Query the service device cluster using UUID
  cisco.mso.ndo_service_device_cluster:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_device_template
    uuid: '{{ add_device1.current.uuid }}'
    state: query
  register: query_device_uuid

- name: Query all the device clusters
  cisco.mso.ndo_service_device_cluster:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_device_template
    state: query
  register: query_all

- name: Remove the service device cluster
  cisco.mso.ndo_service_device_cluster:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_device_template
    name: device1
    state: absent
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data, snake_to_camel
from ansible_collections.cisco.mso.plugins.module_utils.schemas import MSOSchemas
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        name=dict(type="str", aliases=["service_device_cluster"]),
        uuid=dict(type="str", aliases=["service_device_cluster_uuid"]),
        description=dict(type="str"),
        device_mode=dict(type="str", choices=["layer1", "layer2", "layer3"]),
        device_type=dict(type="str", choices=["firewall", "load_balancer", "other"]),
        interface_properties=dict(
            type="list",
            elements="dict",
            options=dict(
                name=dict(type="str", required=True),
                bd=dict(
                    type="dict",
                    options=dict(
                        name=dict(type="str", required=True),
                        template=dict(type="str"),
                        template_id=dict(type="str"),
                        schema=dict(type="str"),
                        schema_id=dict(type="str"),
                    ),
                    required_one_of=[
                        ["schema", "schema_id"],
                        ["template", "template_id"],
                    ],
                    mutually_exclusive=[
                        ["schema", "schema_id"],
                        ["template", "template_id"],
                    ],
                ),
                bd_uuid=dict(type="str"),
                external_epg=dict(
                    type="dict",
                    options=dict(
                        name=dict(type="str", required=True),
                        template=dict(type="str"),
                        template_id=dict(type="str"),
                        schema=dict(type="str"),
                        schema_id=dict(type="str"),
                    ),
                    required_one_of=[
                        ["schema", "schema_id"],
                        ["template", "template_id"],
                    ],
                    mutually_exclusive=[
                        ["schema", "schema_id"],
                        ["template", "template_id"],
                    ],
                ),
                external_epg_uuid=dict(type="str"),
                ipsla_monitoring_policy=dict(
                    type="dict",
                    options=dict(
                        name=dict(type="str"),
                        template=dict(type="str"),
                        template_id=dict(type="str"),
                    ),
                    required_by={
                        "template": "name",
                        "template_id": "name",
                    },
                    mutually_exclusive=[
                        ["template", "template_id"],
                    ],
                ),
                ipsla_monitoring_policy_uuid=dict(type="str"),
                qos_policy=dict(
                    type="dict",
                    options=dict(
                        name=dict(type="str"),
                        template=dict(type="str"),
                        template_id=dict(type="str"),
                    ),
                    required_by={
                        "template": "name",
                        "template_id": "name",
                    },
                    mutually_exclusive=[
                        ["template", "template_id"],
                    ],
                ),
                qos_policy_uuid=dict(type="str"),
                preferred_group=dict(type="bool"),
                rewrite_source_mac=dict(type="bool"),
                anycast=dict(type="bool"),
                config_static_mac=dict(type="bool", aliases=["static_mac_configuration"]),
                is_backup_redirect_ip=dict(type="bool"),
                load_balance_hashing=dict(type="str", choices=["source_destination_and_protocol", "source_ip", "destination_ip"]),
                pod_aware_redirection=dict(type="bool"),
                resilient_hashing=dict(type="bool"),
                tag_based_sorting=dict(type="bool"),
                min_threshold=dict(type="int"),
                max_threshold=dict(type="int"),
                threshold_down_action=dict(type="str", choices=["permit", "deny", "bypass"]),
            ),
            required_one_of=[["bd", "bd_uuid", "external_epg", "external_epg_uuid"]],
            mutually_exclusive=[
                ["bd", "bd_uuid", "external_epg", "external_epg_uuid"],
                ["ipsla_monitoring_policy", "ipsla_monitoring_policy_uuid"],
                ["qos_policy", "qos_policy_uuid"],
            ],
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["name", "uuid"], True],
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["device_mode", "device_type", "interface_properties"]],
        ],
        required_one_of=[["template", "template_id"]],
        mutually_exclusive=[["template", "template_id"]],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    template_id = module.params.get("template_id")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    device_type = module.params.get("device_type")
    device_mode = module.params.get("device_mode")
    state = module.params.get("state")

    ops = []
    match = None
    device_path = None

    reference_dict = {
        "qos": {
            "name": "qosPolicyName",
            "reference": "qosPolicyRef",
            "type": "qos",
            "template": "qosPolicyTemplateName",
            "templateId": "qosPolicyTemplateId",
        },
        "ipsla": {
            "name": "ipslaMonitoringPolicyName",
            "reference": "ipslaMonitoringRef",
            "type": "ipslaMonitoringPolicy",
            "template": "ipslaMonitoringPolicyTemplateName",
            "templateId": "ipslaMonitoringPolicyTemplateId",
        },
        "l3out": {
            "name": "externalEpgName",
            "reference": "externalEpgRef",
            "template": "externalEpgTemplateName",
            "templateId": "externalEpgTemplateId",
            "schema": "externalEpgSchemaName",
            "schemaId": "externalEpgSchemaId",
            "type": "externalEpg",
        },
        "bd": {
            "name": "bdName",
            "reference": "bdRef",
            "template": "bdTemplateName",
            "templateId": "bdTemplateId",
            "schema": "bdSchemaName",
            "schemaId": "bdSchemaId",
            "type": "bd",
        },
    }

    mso_template = MSOTemplate(mso, "service_device", template, template_id)
    mso_template.validate_template("serviceDevice")
    if module.params.get("interface_properties") is not None:
        interface_properties = get_interfaces_payload(mso, mso_template, module.params.get("interface_properties"), reference_dict)
    object_description = "Service Device Cluster"
    path = "/deviceTemplate/template/devices"

    existing_devices = mso_template.template.get("deviceTemplate", {}).get("template", {}).get("devices") or []

    if name or uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_devices,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            device_path = "{0}/{1}".format(path, match.index)
            mso_template.update_config_with_template_and_references(match.details, reference_dict)
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = [mso_template.update_config_with_template_and_references(device, reference_dict) for device in existing_devices]

    if state == "present":
        mso_values = dict(
            name=name,
            description=description,
            deviceLocation="onPremise",
            deviceMode=device_mode,
            deviceType=snake_to_camel(device_type),
            connectivityMode="advanced" if len(interface_properties) >= 3 else ("oneArm" if len(interface_properties) == 1 else "twoArm"),
            interfaces=interface_properties,
        )

        if match:
            append_update_ops_data(ops, match.details, device_path, mso_values)
            mso.sanitize(match.details, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="{0}/-".format(path), value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=device_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        devices = response.get("deviceTemplate", {}).get("template", {}).get("devices") or []
        match = mso_template.get_object_by_key_value_pairs(object_description, devices, [KVPair("uuid", uuid) if uuid else KVPair("name", name)])
        if match:
            mso_template.update_config_with_template_and_references(match.details, reference_dict)
            mso.existing = match.details
        else:
            mso.existing = {}
    elif module.check_mode and state != "query":
        mso_template.update_config_with_template_and_references(mso.proposed, reference_dict)
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def get_interfaces_payload(mso, mso_template, interfaces, reference_dict):

    schema = MSOSchemas(mso)
    templates = MSOTemplates(mso)

    payload = []
    for interface in interfaces:
        mso.check_template_when_name_is_provided(interface.get("ipsla_monitoring_policy"))
        mso.check_template_when_name_is_provided(interface.get("qos_policy"))

        interface_payload = {
            "name": interface.get("name"),
            "redirect": True,
            "isAdvancedIntfConfig": True,
            "ipslaMonitoringRef": templates.get_object_uuid_from_template(
                "tenant", "ipslaMonitoringPolicies", interface.get("ipsla_monitoring_policy_uuid"), interface.get("ipsla_monitoring_policy")
            ),
            "advancedIntfConfig": {
                "rewriteSourceMac": interface.get("rewrite_source_mac"),
                "anycast": interface.get("anycast"),
                "configStaticMac": interface.get("config_static_mac"),
                "isBackupRedirectIP": interface.get("is_backup_redirect_ip"),
                "loadBalanceHashing": snake_to_camel(interface.get("load_balance_hashing"), ["ip"]),
                "podAwareRedirection": interface.get("pod_aware_redirection"),
                "preferredGroup": interface.get("preferred_group"),
                "resilientHashing": interface.get("resilient_hashing"),
                "qosPolicyRef": templates.get_object_uuid_from_template(
                    "tenant", "qosPolicies", interface.get("qos_policy_uuid"), interface.get("qos_policy")
                ),
                "tag": interface.get("tag_based_sorting"),
                "thresholdForRedirect": {
                    "maxThreshold": interface.get("max_threshold"),
                    "minThreshold": interface.get("min_threshold"),
                    "thresholdDownAction": interface.get("threshold_down_action"),
                },
            },
        }
        interface_payload["deviceInterfaceType"] = "l3out"
        interface_type = "external_epg"
        if interface.get("bd_uuid") or interface.get("bd"):
            interface_payload["deviceInterfaceType"] = interface_type = "bd"
        interface_uuid = interface.get("bd_uuid") or interface.get("external_epg_uuid")
        if interface_uuid is None:
            existing_schema = schema.get_template_from_schema(
                interface[interface_type].get("schema"),
                interface[interface_type].get("schema_id"),
                interface[interface_type].get("template"),
                interface[interface_type].get("template_id"),
            )
            if interface_type == "bd":
                existing_schema.set_template_bd(interface["bd"].get("name"), fail_module=True)
                interface_uuid = existing_schema.schema_objects.get("template_bd").details.get("uuid")
            else:
                existing_schema.set_template_external_epg(interface["external_epg"].get("name"), fail_module=True)
                interface_uuid = existing_schema.schema_objects.get("template_external_epg").details.get("uuid")
        interface_payload[reference_dict[interface_payload["deviceInterfaceType"]].get("reference")] = interface_uuid
        if interface_payload.get("ipslaMonitoringRef"):
            interface_payload["advancedIntfConfig"]["advancedTrackingOptions"] = True
        if interface_payload.get("advancedIntfConfig", {}).get("thresholdForRedirect", {}).get("thresholdDownAction"):
            interface_payload["advancedIntfConfig"]["thresholdForRedirectDestination"] = True
        payload.append(interface_payload)
    return payload


if __name__ == "__main__":
    main()
