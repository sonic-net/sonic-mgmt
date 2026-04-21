#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

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
module: ndo_qos_class_policy
version_added: "2.11.0"
short_description: Manage QoS Class Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Quality of Service (QoS) Class Policies.
- This module can be used on Cisco Nexus Dashboard Orchestrator (NDO).
- There can only be a single QoS Class policy in a fabric policy template.
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Gaspard Micol (@gmicol)
options:
  template:
    description:
    - The name of the template.
    - The template must be a fabric policy template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the fabric policy template.
    - This parameter or O(template) is required.
    type: str
  name:
    description:
    - The name of the QoS Class Policy.
    type: str
    aliases: [ qos_class_policy ]
  uuid:
    description:
    - The UUID of the QoS Class Policy.
    type: str
    aliases: [ qos_class_policy_uuid ]
  description:
    description:
    - The description of the QoS Class Policy.
    type: str
  preserve_cos:
    description:
    - Whether to preserve the Class of Service (CoS).
    - Defaults to true when unset during creation.
    type: bool
  qos_levels:
    description:
    - The list of configurable QoS levels for the QoS Class Policy.
    - Providing a new list of O(qos_levels) will replace the existing one from the QoS Class Policy.
    - Providing an empty list will remove the O(qos_levels=[]) from the QoS Class Policy.
    type: list
    elements: dict
    suboptions:
      level:
        description:
        - The QoS level.
        type: str
        choices: [ level1, level2, level3, level4, level5, level6 ]
        required: true
      mtu:
        description:
        - The MTU value.
        - The value must be between 1500 and 9216.
        - Defaults to 9216 when unset during creation.
        type: int
      minimum_buffer:
        description:
        - The minimum number of reserved buffers.
        - The value must be between 0 and 3.
        - Defaults to 0 when unset during creation.
        type: int
      congestion_algorithm:
        description:
        - The congestion algorithm used for this QoS Level.
        - Defaults to C(tail_drop) when unset during creation.
        type: str
        choices: [ tail_drop, wred ]
      wred_configuration:
        description:
        - The Weighted Random Early Detection (WRED) Algorithm configuration.
        - Providing a new list of O(qos_levels.wred_configuration) will replace the existing one from the list of QoS levels.
        - Providing an empty list will remove the O(qos_levels.wred_configuration=[]) from the list of QoS levels.
          from the QoS Class Policy.
        type: dict
        suboptions:
          congestion_notification:
            description:
            - The state of Explicit Congestion Notification (ECN) setting.
            - Enabling Congestion Notification causes the packets that would be dropped to be ECN-marked instead.
            - Defaults to C(disabled) when unset during creation.
            type: str
            choices: [ enabled, disabled ]
          forward_non_ecn_traffic:
            description:
            - Whether to forward Non-ECN Traffic.
            - This attribute should only be used when O(qos_levels.wred_configuration.congestion_notification="enabled").
            - Defaults to false when unset during creation.
            type: bool
          minimum_threshold:
            description:
            - The minimum queue threshold as a percentage of the maximum queue length for WRED algorithm.
            - The value must be between 0 and 100.
            - Defaults to 0 when unset during creation.
            type: int
          maximum_threshold:
            description:
            - The maximum queue threshold as a percentage of the maximum queue length for WRED algorithm.
            - The value must be between 0 and 100.
            - Defaults to 100 when unset during creation.
            type: int
          probability:
            description:
            - The probability value for WRED algorithm.
            - The probability used to determine whether a packet is dropped or queued
              when the average queue size is between the minimum and the maximum threshold values.
            - The value must be between 0 and 100.
            - Defaults to 0 when unset during creation.
            type: int
          weight:
            description:
            - The weight value for WRED algorithm.
            - Lower weight prioritizes current queue length, while higher weight prioritizes older queue lengths.
            - The value must be between 0 and 7.
            - Defaults to 0 when unset during creation.
            type: int
      scheduling_algorithm:
        description:
        - The QoS Scheduling Algorithm.
        - Defaults to C(weighted_round_robin) when unset during creation.
        type: str
        choices: [ weighted_round_robin, strict_priority ]
      bandwidth_allocated:
        description:
        - The percentage of total bandwidth allocated to this QoS Level.
        - The value must be between 0 and 100.
        - Defaults to 20 when unset during creation.
        type: int
      pfc_admin_state:
        description:
        - The administrative state of the Priority Flow Control (PFC) policy.
        type: str
        choices: [ enabled, disabled ]
        default: disabled
      admin_state:
        description:
        - The policy administrative state.
        - Defaults to C(enabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      no_drop_cos:
        description:
        - The Class of Service (CoS) level for which to enforce the no drop packet handling even in case of traffic congestion.
        - This attribute must be specified when O(qos_levels.pfc_admin_state="enabled").
        - Defaults to C(unspecified) when unset during creation.
        type: str
        choices: [ cos0, cos1, cos2, cos3, cos4, cos5, cos6, cos7, unspecified ]
      pfc_scope:
        description:
        - The PFC scope.
        - Defaults to C(fabric_wide) when unset during creation.
        type: str
        choices: [ fabric_wide, intra_tor ]
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
  The M(cisco.mso.ndo_template) module can be used for this.
- Attempts to create any additional QoS Class policies will only update the existing
  object in the Fabric Policy template.
seealso:
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new QoS Class policy with minimum configuration
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    state: present
  register: create_qos_class_policy

- name: Update a QoS Class policy using UUID by adding QoS level1 with minimum configuration
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ create_qos_class_policy.current.uuid }}"
    description: Ansible Test QoS Class Policy
    preserve_cos: true
    qos_levels:
      - level: level1
    state: present
  register: update_qos_class_policy_with_qos_level1

- name: Update a QoS Class policy by adding QoS level2 with full configuration
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    description: Ansible Test QoS Class Policy
    preserve_cos: true
    qos_levels:
      - level: level1
      - level: level2
        mtu: 9000
        minimum_buffer: 1
        congestion_algorithm: wred
        wred_configuration:
          congestion_notification: enabled
          forward_non_ecn_traffic: false
          minimum_threshold: 5
          maximum_threshold: 95
          probability: 80
          weight: 1
        scheduling_algorithm: weighted_round_robin
        bandwidth_allocated: 50
        pfc_admin_state: enabled
        admin_state: enabled
        no_drop_cos: cos1
        pfc_scope: intra_tor
    state: present
  register: add_qos_class_policy_level2

- name: Update a QoS Class policy by removing QoS level2 and keeping QoS level1
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    description: Ansible Test QoS Class Policy
    preserve_cos: true
    qos_levels:
      - level: level1
    state: present
  register: remove_qos_class_policy_level2

- name: Update a QoS Class policy by removing all QoS levels
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    description: Ansible Test QoS Class Policy
    preserve_cos: true
    qos_levels: []
    state: present
  register: remove_qos_class_policy_all_levels

- name: Query QoS Class policy using name
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    state: query
  register: query_one

- name: Query QoS Class policy using UUID
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ create_qos_class_policy.current.uuid }}"
    state: query
  register: query_one_uuid

- name: Delete a QoS Class policy using name
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: ansible_test_qos_class_policy
    state: absent

- name: Delete a QoS Class policy using UUID
  cisco.mso.ndo_qos_class_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ query_one.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""
import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data, delete_none_values
from ansible_collections.cisco.mso.plugins.module_utils.constants import (
    QOS_CONGESTION_ALGORITHM_MAP,
    QOS_SCHEDULING_ALGORITHM_MAP,
    QOS_PFC_SCOPE_MAP,
    QOS_LEVEL,
    COS_VALUES,
)


def main():
    qos_levels_to_remove = copy.copy(QOS_LEVEL)  # A list that tracks of all levels to be removed during the PATCH operation when qos_levels is being updated
    qos_levels_to_remove.remove("unspecified")  # "unspecified" is removed as it is not a valid value for qos_levels.level
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        name=dict(type="str", aliases=["qos_class_policy"]),
        description=dict(type="str"),
        uuid=dict(type="str", aliases=["qos_class_policy_uuid"]),
        preserve_cos=dict(type="bool"),
        qos_levels=dict(
            type="list",
            elements="dict",
            options=dict(
                level=dict(type="str", required=True, choices=qos_levels_to_remove),
                mtu=dict(type="int"),
                minimum_buffer=dict(type="int"),
                congestion_algorithm=dict(type="str", choices=list(QOS_CONGESTION_ALGORITHM_MAP)),
                wred_configuration=dict(
                    type="dict",
                    options=dict(
                        congestion_notification=dict(type="str", choices=["enabled", "disabled"]),
                        forward_non_ecn_traffic=dict(type="bool"),
                        minimum_threshold=dict(type="int"),
                        maximum_threshold=dict(type="int"),
                        probability=dict(type="int"),
                        weight=dict(type="int"),
                    ),
                ),
                scheduling_algorithm=dict(type="str", choices=list(QOS_SCHEDULING_ALGORITHM_MAP)),
                bandwidth_allocated=dict(type="int"),
                pfc_admin_state=dict(type="str", choices=["enabled", "disabled"], default="disabled"),
                admin_state=dict(type="str", choices=["enabled", "disabled"]),
                no_drop_cos=dict(type="str", choices=COS_VALUES),
                pfc_scope=dict(type="str", choices=list(QOS_PFC_SCOPE_MAP)),
            ),
            required_if=[
                ["pfc_admin_state", "enabled", ["no_drop_cos"]],
            ],
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
        required_one_of=[
            ["template", "template_id"],
        ],
        mutually_exclusive=[
            ["template", "template_id"],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    template_id = module.params.get("template_id")
    name = module.params.get("name")
    description = module.params.get("description")
    uuid = module.params.get("uuid")
    preserve_cos = module.params.get("preserve_cos")
    qos_levels = module.params.get("qos_levels")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_policy", template, template_id)
    mso_template.validate_template("fabricPolicy")
    object_description = "QoS Class Policy"

    path = "/fabricPolicyTemplate/template/qosClass"
    existing_qos_policies = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {}).get("qosClass", {})
    if name or uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            [existing_qos_policies],
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(mso_template.update_config_with_template_and_references(match.details))
    else:
        mso.existing = mso.previous = mso_template.update_config_with_template_and_references(existing_qos_policies)

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        mso_values = {
            "name": name,
            "description": description,
            "preserveCos": preserve_cos,
        }
        if qos_levels is not None:
            for qos_level in qos_levels:
                level = qos_level.get("level")
                if level not in qos_levels_to_remove:
                    mso.fail_json(msg="Duplicate configurations for QoS {0}".format(level))
                else:
                    qos_levels_to_remove.remove(level)

                wred_configuration = None
                if qos_level.get("wred_configuration"):
                    wred_configuration = {
                        "congestionNotification": qos_level["wred_configuration"].get("congestion_notification"),
                        "minThreshold": qos_level["wred_configuration"].get("minimum_threshold"),
                        "maxThreshold": qos_level["wred_configuration"].get("maximum_threshold"),
                        "probability": qos_level["wred_configuration"].get("probability"),
                        "weight": qos_level["wred_configuration"].get("weight"),
                        "forwardNonEcn": qos_level["wred_configuration"].get("forward_non_ecn_traffic"),
                    }

                mso_values[level] = {
                    "adminState": qos_level.get("admin_state"),
                    "minBuffer": qos_level.get("minimum_buffer"),
                    "mtu": qos_level.get("mtu"),
                    "congestionAlgorithm": QOS_CONGESTION_ALGORITHM_MAP.get(qos_level.get("congestion_algorithm")),
                    "wredConfig": wred_configuration,
                    "schedulingAlgorithm": QOS_SCHEDULING_ALGORITHM_MAP.get(qos_level.get("scheduling_algorithm")),
                    "bandwidthAllocated": qos_level.get("bandwidth_allocated"),
                    "pfcAdminState": qos_level.get("pfc_admin_state"),
                    "noDropCoS": qos_level.get("no_drop_cos"),
                    "pfcScope": QOS_PFC_SCOPE_MAP.get(qos_level.get("pfc_scope")),
                }
        else:
            qos_levels_to_remove = []

        mso_values = delete_none_values(mso_values)

        if match:
            append_update_ops_data(ops, match.details, path, mso_values, remove_data=qos_levels_to_remove)
            mso.sanitize(match.details, collate=True)

        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=path, value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        qos_policies = response.get("fabricPolicyTemplate", {}).get("template", {}).get("qosClass", {})
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            [qos_policies],
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            mso.existing = mso_template.update_config_with_template_and_references(match.details)
        else:
            mso.existing = {}
    elif module.check_mode and state != "query":
        mso_template.update_config_with_template_and_references(mso.proposed)
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
