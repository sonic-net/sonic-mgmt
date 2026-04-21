#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Shreyas Srish (@shrsr) <ssrish@cisco.com>

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
module: ndo_qos_dscp_cos_translation_policy
short_description: Manage QoS DSCP CoS Translation Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Quality of Service (QoS) Differentiated Services Code Point (DSCP) Class of Service (CoS) Translation Policies.
- This module can be used on Cisco Nexus Dashboard Orchestrator (NDO).
- There can only be a single QoS DSCP CoS translation policy in a fabric policy template.
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Shreyas Srish (@shrsr)
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
  qos_dscp_translation_policy:
    description:
    - The name of the QoS DSCP Translation Policy.
    type: str
    aliases: [ name ]
  description:
    description:
    - The description of the QoS DSCP Translation Policy.
    type: str
  qos_dscp_translation_policy_uuid:
    description:
    - The UUID of the QoS DSCP Translation Policy.
    type: str
    aliases: [ uuid ]
  admin_state:
    description:
    - The administrative state of the policy.
    type: str
    choices: [ enabled, disabled ]
  control_plane_traffic:
    description:
    - DSCP value for control plane traffic.
    type: str
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
      - unspecified
      - voice_admit
  policy_plane_traffic:
    description:
    - DSCP value for policy plane traffic.
    type: str
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
      - unspecified
      - voice_admit
  span_traffic:
    description:
    - DSCP value for SPAN traffic.
    type: str
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
      - unspecified
      - voice_admit
  traceroute_traffic:
    description:
    - DSCP value for traceroute traffic.
    type: str
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
      - unspecified
      - voice_admit
  level1:
    description:
    - DSCP value for level 1 traffic.
    type: str
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
      - unspecified
      - voice_admit
  level2:
    description:
    - DSCP value for level 2 traffic.
    type: str
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
      - unspecified
      - voice_admit
  level3:
    description:
    - DSCP value for level 3 traffic.
    type: str
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
      - unspecified
      - voice_admit
  level4:
    description:
    - DSCP value for level 4 traffic.
    type: str
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
      - unspecified
      - voice_admit
  level5:
    description:
    - DSCP value for level 5 traffic.
    type: str
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
      - unspecified
      - voice_admit
  level6:
    description:
    - DSCP value for level 6 traffic.
    type: str
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
      - unspecified
      - voice_admit
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
- Attempts to create any additional QoS DSCP CoS translation policies will only update the existing
  object in the Fabric Policy template.
seealso:
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new QoS DSCP Translation policy
  cisco.mso.ndo_qos_dscp_cos_translation_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    qos_dscp_translation_policy: ansible_test_qos_dscp_policy
    admin_state: enabled
    control_plane_traffic: cs0
    policy_plane_traffic: cs4
    span_traffic: cs5
    traceroute_traffic: cs6
    level1: cs1
    level2: cs2
    level3: cs3
    level4: af11
    level5: af21
    level6: af31
    state: present
  register: create_qos_dscp_translation_policy

- name: Query QoS DSCP Translation policy with name
  cisco.mso.ndo_qos_dscp_cos_translation_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    qos_dscp_translation_policy: ansible_test_qos_dscp_policy
    state: query
  register: query_one

- name: Query QoS DSCP Translation policy with uuid
  cisco.mso.ndo_qos_dscp_cos_translation_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    qos_dscp_translation_policy_uuid: "{{ create_qos_dscp_translation_policy.current.uuid }}"
    state: query
  register: query_one_uuid

- name: Delete a QoS DSCP Translation policy with name
  cisco.mso.ndo_qos_dscp_cos_translation_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    qos_dscp_translation_policy: ansible_test_qos_dscp_policy
    state: absent

- name: Delete a QoS DSCP Translation policy with uuid
  cisco.mso.ndo_qos_dscp_cos_translation_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    qos_dscp_translation_policy_uuid: "{{ query_one.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""
import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
)
from ansible_collections.cisco.mso.plugins.module_utils.template import (
    MSOTemplate,
    KVPair,
)
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data
from ansible_collections.cisco.mso.plugins.module_utils.constants import TARGET_DSCP_MAP


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        qos_dscp_translation_policy=dict(type="str", aliases=["name"]),
        description=dict(type="str"),
        qos_dscp_translation_policy_uuid=dict(type="str", aliases=["uuid"]),
        admin_state=dict(type="str", choices=["enabled", "disabled"]),
        control_plane_traffic=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        policy_plane_traffic=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        span_traffic=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        traceroute_traffic=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        level1=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        level2=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        level3=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        level4=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        level5=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        level6=dict(type="str", choices=list(TARGET_DSCP_MAP)),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["qos_dscp_translation_policy", "qos_dscp_translation_policy_uuid"], True],
            ["state", "present", ["qos_dscp_translation_policy", "qos_dscp_translation_policy_uuid"], True],
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
    qos_dscp_translation_policy = module.params.get("qos_dscp_translation_policy")
    description = module.params.get("description")
    qos_dscp_translation_policy_uuid = module.params.get("qos_dscp_translation_policy_uuid")
    admin_state = module.params.get("admin_state")
    control_plane_traffic = TARGET_DSCP_MAP.get(module.params.get("control_plane_traffic"))
    policy_plane_traffic = TARGET_DSCP_MAP.get(module.params.get("policy_plane_traffic"))
    span_traffic = TARGET_DSCP_MAP.get(module.params.get("span_traffic"))
    traceroute_traffic = TARGET_DSCP_MAP.get(module.params.get("traceroute_traffic"))
    level1 = TARGET_DSCP_MAP.get(module.params.get("level1"))
    level2 = TARGET_DSCP_MAP.get(module.params.get("level2"))
    level3 = TARGET_DSCP_MAP.get(module.params.get("level3"))
    level4 = TARGET_DSCP_MAP.get(module.params.get("level4"))
    level5 = TARGET_DSCP_MAP.get(module.params.get("level5"))
    level6 = TARGET_DSCP_MAP.get(module.params.get("level6"))
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_policy", template, template_id)
    mso_template.validate_template("fabricPolicy")
    object_description = "QoS DSCP CoS Translation Policy"

    path = "/fabricPolicyTemplate/template/qosDscpTranslation"
    existing_qos_policies = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {}).get("qosDscpTranslation", {})
    if qos_dscp_translation_policy or qos_dscp_translation_policy_uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            [existing_qos_policies],
            [KVPair("uuid", qos_dscp_translation_policy_uuid) if qos_dscp_translation_policy_uuid else KVPair("name", qos_dscp_translation_policy)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_qos_policies

    if state == "present":
        mso_values = dict(
            name=qos_dscp_translation_policy,
            description=description,
            adminState=admin_state,
            controlPlaneTraffic=control_plane_traffic,
            policyPlaneTraffic=policy_plane_traffic,
            spanTraffic=span_traffic,
            tracerouteTraffic=traceroute_traffic,
            level1=level1,
            level2=level2,
            level3=level3,
            level4=level4,
            level5=level5,
            level6=level6,
        )
        if match:
            append_update_ops_data(ops, match.details, path, mso_values)
            mso.sanitize(match.details, collate=True)

        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=path, value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        qos_policies = response.get("fabricPolicyTemplate", {}).get("template", {}).get("qosDscpTranslation", {})
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            [qos_policies],
            [KVPair("uuid", qos_dscp_translation_policy_uuid) if qos_dscp_translation_policy_uuid else KVPair("name", qos_dscp_translation_policy)],
        )
        if match:
            mso.existing = match.details
        else:
            mso.existing = {}
    elif module.check_mode and state != "query":
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
