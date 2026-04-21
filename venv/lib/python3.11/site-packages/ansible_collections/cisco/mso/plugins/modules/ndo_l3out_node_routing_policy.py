#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_l3out_node_routing_policy
short_description: Manage L3Out Node Routing Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage L3Out Node Routing Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the template.
    - The template must be a Tenant Policy Template.
    type: str
    required: true
  name:
    description:
    - The name of the L3Out Node Routing Policy.
    type: str
    aliases: [ l3out_node_routing_policy_name ]
  uuid:
    description:
    - The UUID of the L3Out Node Routing Policy.
    - This parameter is required when the O(name) needs to be updated.
    type: str
    aliases: [ l3out_node_routing_policy_uuid ]
  description:
    description:
    - The description of the L3Out Node Routing Policy.
    type: str
  bfd_multi_hop_settings:
    description:
    - The BFD MultiHop Settings configuration of the L3Out Node Routing Policy.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the BFD MultiHop Settings.
        - Use C(disabled) to remove the BFD MultiHop Settings.
        type: str
        choices: [ enabled, disabled ]
      admin_state:
        description:
        - The administrative state of the BFD MultiHop Settings.
        - Defaults to enabled when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      detection_multiplier:
        description:
        - The detection multiplier of the BFD MultiHop Settings.
        - Defaults to 3 when unset during creation.
        - The value must be between 1 and 50.
        type: int
      min_receive_interval:
        description:
        - The minimum receive interval of the BFD MultiHop Settings.
        - Defaults to 250 when unset during creation.
        - The value must be between 250 and 999 microseconds.
        type: int
      min_transmit_interval:
        description:
        - The minimum transmit interval of the BFD MultiHop Settings.
        - Defaults to 250 when unset during creation.
        - The value must be between 250 and 999 microseconds.
        type: int
  bgp_node_settings:
    description:
    - The BGP Node Settings configuration of the L3Out Node Routing Policy.
    type: dict
    suboptions:
      state:
        description:
        - Use C(enabled) to configure the BGP Node Settings.
        - Use C(disabled) to remove the BGP Node Settings.
        type: str
        choices: [ enabled, disabled ]
      graceful_restart_helper:
        description:
        - The graceful restart helper of the BGP Node Settings.
        - Defaults to enabled when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      keep_alive_interval:
        description:
        - The keep alive interval of the BGP Node Settings.
        - Defaults to 60 when unset during creation.
        - The value must be between 0 and 3600 seconds.
        type: int
      hold_interval:
        description:
        - The hold interval of the BGP Node Settings.
        - Defaults to 180 when unset during creation.
        - The value must be 0 or between 3 and 3600 seconds.
        type: int
      stale_interval:
        description:
        - The stale interval of the BGP Node Settings.
        - Defaults to 300 when unset during creation.
        - The value must be between 1 and 3600 seconds.
        type: int
      max_as_limit:
        description:
        - The max as limit of the BGP Node Settings.
        - Defaults to 0 when unset during creation.
        - The value must be between 0 and 2000.
        type: int
  as_path_multipath_relax:
    description:
    - The BGP Best Path Control of the L3Out Node Routing Policy.
    - Providing an empty string will remove the O(as_path_multipath_relax="") from the L3Out Node Routing Policy.
    type: str
    choices: [ enabled, disabled, "" ]
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
  Use M(cisco.mso.ndo_template) to create the Tenant Policy Template.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new L3Out Node Routing Policy with empty bgp_node and bfd_multi_hop settings
  cisco.mso.ndo_l3out_node_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: nrp_1
    bfd_multi_hop_settings:
      state: enabled
    bgp_node_settings:
      state: enabled
    as_path_multipath_relax: disabled
    state: present

- name: Create a new L3Out Node Routing Policy with full config of bgp_node and bfd_multi_hop settings
  cisco.mso.ndo_l3out_node_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: nrp_2
    bfd_multi_hop_settings:
      admin_state: enabled
      detection_multiplier: 10
      min_receive_interval: 450
      min_transmit_interval: 550
    bgp_node_settings:
      graceful_restart_helper: enabled
      keep_alive_interval: 15
      hold_interval: 115
      stale_interval: 215
      max_as_limit: 25
    as_path_multipath_relax: disabled
    state: present
  register: nrp_2

- name: Update L3Out Node Routing Policy name and bgp_node_settings attributes
  cisco.mso.ndo_l3out_node_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ nrp_2.current.uuid }}"
    name: nrp_2_updated
    bgp_node_settings:
      graceful_restart_helper: disabled
      keep_alive_interval: 20
    state: present

- name: Query a L3Out Node Routing Policies with name
  cisco.mso.ndo_l3out_node_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: nrp_1
    state: query
  register: query_with_name

- name: Query a L3Out Node Routing Policies with UUID
  cisco.mso.ndo_l3out_node_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ query_with_name.current.uuid }}"
    state: query
  register: query_with_uuid

- name: Query all L3Out Node Routing Policies
  cisco.mso.ndo_l3out_node_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Delete a L3Out Node Routing Policy
  cisco.mso.ndo_l3out_node_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: nrp_1
    state: absent

- name: Delete a L3Out Node Routing Policy using UUID
  cisco.mso.ndo_l3out_node_routing_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ query_with_name.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""


import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, ndo_bfd_multi_hop_settings_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True),
        name=dict(type="str", aliases=["l3out_node_routing_policy_name"]),
        uuid=dict(type="str", aliases=["l3out_node_routing_policy_uuid"]),
        description=dict(type="str"),
        bfd_multi_hop_settings=ndo_bfd_multi_hop_settings_spec(),
        bgp_node_settings=dict(
            type="dict",
            options=dict(
                state=dict(type="str", choices=["enabled", "disabled"]),
                graceful_restart_helper=dict(type="str", choices=["enabled", "disabled"]),
                keep_alive_interval=dict(type="int"),  # sec
                hold_interval=dict(type="int"),  # sec
                stale_interval=dict(type="int"),  # sec
                max_as_limit=dict(type="int"),
            ),
        ),
        as_path_multipath_relax=(dict(type="str", choices=["enabled", "disabled", ""])),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    bfd_multi_hop_settings = module.params.get("bfd_multi_hop_settings")
    bgp_node_settings = module.params.get("bgp_node_settings")
    as_path_multipath_relax = module.params.get("as_path_multipath_relax")
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "tenant", template)
    mso_template.validate_template("tenantPolicy")

    path = "/tenantPolicyTemplate/template/l3OutNodePolGroups"

    l3out_node_routing_policy = mso_template.get_l3out_node_routing_policy_object(uuid, name)

    if uuid or name:
        if l3out_node_routing_policy:
            mso.existing = mso.previous = copy.deepcopy(l3out_node_routing_policy.details)  # Query a specific object
    elif l3out_node_routing_policy:
        mso.existing = l3out_node_routing_policy  # Query all objects

    ops = []
    if state == "present":
        if mso.existing:
            proposed_payload = copy.deepcopy(mso.existing)
            update_path = "{0}/{1}".format(path, l3out_node_routing_policy.index)

            if name and proposed_payload.get("name") != name:
                ops.append(dict(op="replace", path="{0}/name".format(update_path), value=name))
                proposed_payload["name"] = name

            if description is not None and proposed_payload.get("description") != description:
                ops.append(dict(op="replace", path="{0}/description".format(update_path), value=description))
                proposed_payload["description"] = description

            if as_path_multipath_relax is not None and as_path_multipath_relax != "":
                if not proposed_payload.get("asPathPol"):
                    proposed_payload["asPathPol"] = dict()
                    ops.append(dict(op="replace", path="{0}/asPathPol".format(update_path), value=dict()))

                if proposed_payload.get("asPathPol").get("asPathMultipathRelax") is not True if as_path_multipath_relax == "enabled" else False:
                    proposed_payload["asPathPol"]["asPathMultipathRelax"] = True if as_path_multipath_relax == "enabled" else False
                    ops.append(
                        dict(
                            op="replace",
                            path="{0}/asPathPol/asPathMultipathRelax".format(update_path),
                            value=True if as_path_multipath_relax == "enabled" else False,
                        )
                    )
            elif as_path_multipath_relax == "":
                proposed_payload.pop("asPathPol", None)
                ops.append(dict(op="remove", path="{0}/asPathPol".format(update_path)))

            if bfd_multi_hop_settings is not None:
                if bfd_multi_hop_settings.get("state") == "disabled" and proposed_payload.get("bfdMultiHopPol"):
                    proposed_payload.pop("bfdMultiHopPol", None)
                    ops.append(dict(op="remove", path="{0}/bfdMultiHopPol".format(update_path)))

                elif bfd_multi_hop_settings.get("state") != "disabled":
                    if not proposed_payload.get("bfdMultiHopPol"):
                        proposed_payload["bfdMultiHopPol"] = dict()
                        ops.append(dict(op="replace", path="{0}/bfdMultiHopPol".format(update_path), value=dict()))

                    if bfd_multi_hop_settings.get("admin_state") is not None and proposed_payload.get("bfdMultiHopPol").get(
                        "adminState"
                    ) != bfd_multi_hop_settings.get("admin_state"):
                        proposed_payload["bfdMultiHopPol"]["adminState"] = bfd_multi_hop_settings.get("admin_state")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdMultiHopPol/adminState".format(update_path),
                                value=bfd_multi_hop_settings.get("admin_state"),
                            )
                        )

                    if bfd_multi_hop_settings.get("detection_multiplier") is not None and proposed_payload.get("bfdMultiHopPol").get(
                        "detectionMultiplier"
                    ) != bfd_multi_hop_settings.get("detection_multiplier"):
                        proposed_payload["bfdMultiHopPol"]["detectionMultiplier"] = bfd_multi_hop_settings.get("detection_multiplier")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdMultiHopPol/detectionMultiplier".format(update_path),
                                value=bfd_multi_hop_settings.get("detection_multiplier"),
                            )
                        )

                    if bfd_multi_hop_settings.get("min_receive_interval") is not None and proposed_payload.get("bfdMultiHopPol").get(
                        "minRxInterval"
                    ) != bfd_multi_hop_settings.get("min_receive_interval"):
                        proposed_payload["bfdMultiHopPol"]["minRxInterval"] = bfd_multi_hop_settings.get("min_receive_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdMultiHopPol/minRxInterval".format(update_path),
                                value=bfd_multi_hop_settings.get("min_receive_interval"),
                            )
                        )

                    if bfd_multi_hop_settings.get("min_transmit_interval") is not None and proposed_payload.get("bfdMultiHopPol").get(
                        "minTxInterval"
                    ) != bfd_multi_hop_settings.get("min_transmit_interval"):
                        proposed_payload["bfdMultiHopPol"]["minTxInterval"] = bfd_multi_hop_settings.get("min_transmit_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bfdMultiHopPol/minTxInterval".format(update_path),
                                value=bfd_multi_hop_settings.get("min_transmit_interval"),
                            )
                        )

            if bgp_node_settings is not None:
                if bgp_node_settings.get("state") == "disabled" and proposed_payload.get("bgpTimerPol"):
                    proposed_payload.pop("bgpTimerPol", None)
                    ops.append(dict(op="remove", path="{0}/bgpTimerPol".format(update_path)))

                elif bgp_node_settings.get("state") != "disabled":
                    if not proposed_payload.get("bgpTimerPol"):
                        proposed_payload["bgpTimerPol"] = dict()
                        ops.append(dict(op="replace", path="{0}/bgpTimerPol".format(update_path), value=dict()))

                    if bgp_node_settings.get("graceful_restart_helper") is not None and (
                        proposed_payload.get("bgpTimerPol").get("gracefulRestartHelper") is not True
                        if bgp_node_settings.get("graceful_restart_helper") == "enabled"
                        else False
                    ):
                        proposed_payload["bgpTimerPol"]["gracefulRestartHelper"] = (
                            True if bgp_node_settings.get("graceful_restart_helper") == "enabled" else False
                        )
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bgpTimerPol/gracefulRestartHelper".format(update_path),
                                value=True if bgp_node_settings.get("graceful_restart_helper") == "enabled" else False,
                            )
                        )

                    if bgp_node_settings.get("keep_alive_interval") is not None and proposed_payload.get("bgpTimerPol").get(
                        "keepAliveInterval"
                    ) != bgp_node_settings.get("keep_alive_interval"):
                        proposed_payload["bgpTimerPol"]["keepAliveInterval"] = bgp_node_settings.get("keep_alive_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bgpTimerPol/keepAliveInterval".format(update_path),
                                value=bgp_node_settings.get("keep_alive_interval"),
                            )
                        )

                    if bgp_node_settings.get("hold_interval") is not None and proposed_payload.get("bgpTimerPol").get("holdInterval") != bgp_node_settings.get(
                        "hold_interval"
                    ):
                        proposed_payload["bgpTimerPol"]["holdInterval"] = bgp_node_settings.get("hold_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bgpTimerPol/holdInterval".format(update_path),
                                value=bgp_node_settings.get("hold_interval"),
                            )
                        )

                    if bgp_node_settings.get("stale_interval") is not None and proposed_payload.get("bgpTimerPol").get(
                        "staleInterval"
                    ) != bgp_node_settings.get("stale_interval"):
                        proposed_payload["bgpTimerPol"]["staleInterval"] = bgp_node_settings.get("stale_interval")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bgpTimerPol/staleInterval".format(update_path),
                                value=bgp_node_settings.get("stale_interval"),
                            )
                        )

                    if bgp_node_settings.get("max_as_limit") is not None and proposed_payload.get("bgpTimerPol").get("maxAslimit") != bgp_node_settings.get(
                        "max_as_limit"
                    ):
                        proposed_payload["bgpTimerPol"]["maxAslimit"] = bgp_node_settings.get("max_as_limit")
                        ops.append(
                            dict(
                                op="replace",
                                path="{0}/bgpTimerPol/maxAslimit".format(update_path),
                                value=bgp_node_settings.get("max_as_limit"),
                            )
                        )

            mso.sanitize(proposed_payload)
        else:
            if not (bfd_multi_hop_settings or bgp_node_settings or as_path_multipath_relax):
                mso.fail_json(
                    msg="At least one of the following attributes must be specified when creating L3Out Node Routing Policy:"
                    + " 'bfd_multi_hop_settings', 'bgp_node_settings', or 'as_path_multipath_relax'."
                )

            payload = dict(name=name)
            if description:
                payload["description"] = description

            if as_path_multipath_relax:  # initially ignores None and "" (empty string)
                # enabled = true
                # disabled = false
                # "" = remove the  "BGP Best Path Control" settings from the object
                payload["asPathPol"] = dict(asPathMultipathRelax=True if as_path_multipath_relax == "enabled" else False)

            if bfd_multi_hop_settings is not None:
                bfd_multi_hop_pol = dict()
                if bfd_multi_hop_settings.get("admin_state"):
                    bfd_multi_hop_pol["adminState"] = bfd_multi_hop_settings.get("admin_state")

                if bfd_multi_hop_settings.get("detection_multiplier"):
                    bfd_multi_hop_pol["detectionMultiplier"] = bfd_multi_hop_settings.get("detection_multiplier")

                if bfd_multi_hop_settings.get("min_receive_interval"):
                    bfd_multi_hop_pol["minRxInterval"] = bfd_multi_hop_settings.get("min_receive_interval")

                if bfd_multi_hop_settings.get("min_transmit_interval"):
                    bfd_multi_hop_pol["minTxInterval"] = bfd_multi_hop_settings.get("min_transmit_interval")

                if bfd_multi_hop_pol or bfd_multi_hop_settings.get("state") == "enabled":
                    payload["bfdMultiHopPol"] = bfd_multi_hop_pol

            if bgp_node_settings is not None:
                bgp_timer_pol = dict()
                if bgp_node_settings.get("graceful_restart_helper"):
                    bgp_timer_pol["gracefulRestartHelper"] = True if bgp_node_settings.get("graceful_restart_helper") == "enabled" else False

                if bgp_node_settings.get("keep_alive_interval"):
                    bgp_timer_pol["keepAliveInterval"] = bgp_node_settings.get("keep_alive_interval")

                if bgp_node_settings.get("hold_interval"):
                    bgp_timer_pol["holdInterval"] = bgp_node_settings.get("hold_interval")

                if bgp_node_settings.get("stale_interval"):
                    bgp_timer_pol["staleInterval"] = bgp_node_settings.get("stale_interval")

                if bgp_node_settings.get("max_as_limit"):
                    bgp_timer_pol["maxAslimit"] = bgp_node_settings.get("max_as_limit")

                if bgp_timer_pol or bgp_node_settings.get("state") == "enabled":
                    payload["bgpTimerPol"] = bgp_timer_pol

            ops.append(dict(op="add", path="{0}/-".format(path), value=copy.deepcopy(payload)))

            mso.sanitize(payload)
    elif state == "absent":
        if mso.existing:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, l3out_node_routing_policy.index)))

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        l3out_node_routing_policy = mso_template.get_l3out_node_routing_policy_object(uuid, name)
        if l3out_node_routing_policy:
            mso.existing = l3out_node_routing_policy.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
