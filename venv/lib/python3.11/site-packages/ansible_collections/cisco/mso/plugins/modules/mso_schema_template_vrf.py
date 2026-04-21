#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>
# Copyright: (c) 2023, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_vrf
short_description: Manage VRFs in schema templates
description:
- Manage VRFs in schema templates on Cisco ACI Multi-Site.
author:
- Akini Ross (@akinross)
- Anvitha Jain (@anvitha-jain)
- Dag Wieers (@dagwieers)
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
  vrf:
    description:
    - The name of the VRF to manage.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  layer3_multicast:
    description:
    - Whether to enable L3 multicast.
    type: bool
  vzany:
    description:
    - Whether to enable vzAny.
    type: bool
  ip_data_plane_learning:
    description:
    - Whether IP data plane learning is enabled or disabled.
    - The APIC defaults to C(enabled) when unset during creation.
    type: str
    choices: [ disabled, enabled ]
  preferred_group:
    description:
    - Whether to enable preferred Endpoint Group.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  site_aware_policy_enforcement:
    description:
    - Whether to enable Site-aware Policy Enforcement Mode.
    - Enabling or Disabling Site-aware Policy Enforcement Mode will cause temporary traffic disruption.
    - Enabling Site-aware Policy Enforcement Mode will increase TCAM usage for existing contracts.
    - Site-aware Policy Enforcement needs to be enabled in the consumer and provider VRF when an inter-VRF contract is required.
    - Contract permit logging cannot be used when Site-aware Policy Enforcement Mode is enabled.
    type: bool
  bd_enforcement_status:
    description:
    - Whether to enable BD Enforcement Status.
    type: bool
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new VRF
  cisco.mso.mso_schema_template_vrf:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF 1
    state: present

- name: Remove an VRF
  cisco.mso.mso_schema_template_vrf:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF1
    state: absent

- name: Query a specific VRFs
  cisco.mso.mso_schema_template_vrf:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF1
    state: query
  register: query_result

- name: Query all VRFs
  cisco.mso.mso_schema_template_vrf:
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
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        vrf=dict(type="str", aliases=["name"]),  # This parameter is not required for querying all objects
        display_name=dict(type="str"),
        layer3_multicast=dict(type="bool"),
        vzany=dict(type="bool"),
        preferred_group=dict(type="bool"),
        ip_data_plane_learning=dict(type="str", choices=["enabled", "disabled"]),
        site_aware_policy_enforcement=dict(type="bool"),
        bd_enforcement_status=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["vrf"]],
            ["state", "present", ["vrf"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    vrf = module.params.get("vrf")
    display_name = module.params.get("display_name")
    layer3_multicast = module.params.get("layer3_multicast")
    vzany = module.params.get("vzany")
    ip_data_plane_learning = module.params.get("ip_data_plane_learning")
    preferred_group = module.params.get("preferred_group")
    site_aware_policy_enforcement = module.params.get("site_aware_policy_enforcement")
    bd_enforcement_status = module.params.get("bd_enforcement_status")
    state = module.params.get("state")

    vrfs_path = "/templates/{0}/vrfs".format(template)

    mso = MSOModule(module)

    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)

    if state == "query":
        if vrf:
            mso_schema.set_template_vrf(vrf)
            mso.existing = mso_schema.schema_objects.get("template_vrf").details
        else:
            mso.existing = mso_schema.schema_objects.get("template").details.get("vrfs", [])
        mso.exit_json()

    mso_schema.set_template_vrf(vrf, False)

    template_vrf = mso_schema.schema_objects.get("template_vrf")
    ops = []

    mso.previous = mso.existing = template_vrf.details if template_vrf else mso.existing

    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path="{0}/{1}".format(vrfs_path, template_vrf.details.get("name"))))

    elif state == "present":
        if display_name is None and not mso.existing:
            display_name = vrf

        payload = dict(
            name=vrf,
            displayName=display_name,
            l3MCast=layer3_multicast,
            vzAnyEnabled=vzany,
            preferredGroup=preferred_group,
            ipDataPlaneLearning=ip_data_plane_learning,
        )

        if site_aware_policy_enforcement is not None:
            payload["siteAwarePolicyEnforcementMode"] = site_aware_policy_enforcement
        if bd_enforcement_status is not None:
            payload["bdEnfStatus"] = bd_enforcement_status

        if template_vrf and template_vrf.details.get("vrfRef"):
            # Add vrfRef from the details to ensure idempotency succeeds
            payload["vrfRef"] = template_vrf.details["vrfRef"]

        mso.sanitize(payload, collate=True)

        if mso.existing:
            vrf_path = "{0}/{1}".format(vrfs_path, template_vrf.details.get("name"))
            if display_name is not None and display_name != mso.existing.get("displayName"):
                ops.append(dict(op="replace", path=vrf_path + "/displayName", value=display_name))
            if layer3_multicast is not None and layer3_multicast != mso.existing.get("l3MCast"):
                ops.append(dict(op="replace", path=vrf_path + "/l3MCast", value=layer3_multicast))
            if vzany is not None and vzany != mso.existing.get("vzAnyEnabled"):
                ops.append(dict(op="replace", path=vrf_path + "/vzAnyEnabled", value=vzany))
            if preferred_group is not None and preferred_group != mso.existing.get("preferredGroup"):
                ops.append(dict(op="replace", path=vrf_path + "/preferredGroup", value=preferred_group))
            if ip_data_plane_learning is not None and ip_data_plane_learning != mso.existing.get("ipDataPlaneLearning"):
                ops.append(dict(op="replace", path=vrf_path + "/ipDataPlaneLearning", value=ip_data_plane_learning))
            if site_aware_policy_enforcement is not None and site_aware_policy_enforcement != mso.existing.get("siteAwarePolicyEnforcementMode"):
                ops.append(dict(op="replace", path=vrf_path + "/siteAwarePolicyEnforcementMode", value=site_aware_policy_enforcement))
            if bd_enforcement_status is not None and bd_enforcement_status != mso.existing.get("bdEnfStatus"):
                ops.append(dict(op="replace", path=vrf_path + "/bdEnfStatus", value=bd_enforcement_status))
        else:
            ops.append(dict(op="add", path=vrfs_path + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode and ops:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
