#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg)
# Copyright: (c) 2023, Akini Ross (@akinross)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_vrf_multicast
short_description: Manage VRF Multicast objects (pim:CtxP)
description:
- Manage VRF Multicast objects on Cisco ACI fabrics.
- Creating I(state=present) enables Protocol Independent Multicast (PIM) on a VRF
- Deleting I(state=absent) disables Protocol Independent Multicast (PIM) on a VRF.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  vrf:
    description:
    - The name of an existing VRF.
    type: str
    aliases: [ vrf_name ]
  pim_setting:
    description: Configuration container for Protocol Independent Multicast (PIM) settings.
    type: dict
    suboptions:
      mtu:
        description:
        - The MTU size supported for multicast.
        - The APIC defaults to C(1500) when unset during creation.
        type: int
      control_state:
        description:
        - The action(s) to take when a loop is detected.
        - Specify C([]) to remove the control state configuration.
        type: list
        elements: str
        aliases: [ control, ctrl ]
        choices: [ fast, strict ]
  resource_policy:
    description: Configuration container for Protocol Independent Multicast (PIM) resource policy.
    type: dict
    suboptions:
      maximum_limit:
        description:
        - The Max Multicast Entries.
        - The APIC defaults to C(unlimited) when unset during creation.
        - Specify C(0) to reset to C(unlimited).
        type: int
        aliases: [ max ]
      reserved_multicast_entries:
        description:
        - The Reserved Multicast Entries.
        - The APIC defaults to C(undefined) when unset during creation.
        - Required when C(reserved_route_map) is provided.
        type: int
        aliases: [ rsvd ]
      reserved_route_map:
        description:
        - The DN of the Route Map.
        - Specify C("") to remove the Route Map configuration.
        - Required when C(reserved_multicast_entries) is provided.
        type: str
        aliases: [ route_map, route_map_dn ]
  any_source_multicast:
    description: Configuration container for Protocol Independent Multicast (PIM) Any Source Multicast (ASM) settings.
    type: dict
    aliases: [ asm, any_source ]
    suboptions:
      shared_range_route_map:
        description:
        - The DN of the Route Map.
        - Specify C("") to remove the Route Map configuration.
        type: str
        aliases: [ shared_range_policy ]
      source_group_expiry_route_map:
        description:
        - The DN of the Route Map.
        - Specify C("") to remove the Route Map configuration.
        type: str
        aliases: [ sg_expiry_route_map ]
      expiry:
        description:
        - The expiry time in seconds.
        - The APIC defaults to C(default-timeout) when unset during creation.
        - Specify C(0) to reset to C(default-timeout).
        type: int
        aliases: [ expiry_seconds ]
      max_rate:
        description:
        - The maximum rate per second.
        - The APIC defaults to C(65535) when unset during creation.
        type: int
        aliases: [ max_rate_per_second ]
      source_ip:
        description:
        - The source IP address.
        type: str
        aliases: [ source, source_ip_address ]
  source_specific_multicast:
    description: Configuration container for Protocol Independent Multicast (PIM) Source Specific Multicast (SSM) settings.
    type: dict
    aliases: [ ssm, specific_source ]
    suboptions:
      group_range_route_map:
        description:
        - The DN of the Route Map.
        - Specify C("") to remove the Route Map configuration.
        type: str
        aliases: [ group_range_policy ]
  bootstrap_router:
    description: Configuration container for Protocol Independent Multicast (PIM) Bootstrap Router (BSR) settings.
    type: dict
    aliases: [ bsr, bootstrap ]
    suboptions:
      bsr_filter:
        description:
        - The DN of the Route Map.
        - Specify C("") to remove the Route Map configuration.
        type: str
        aliases: [ filter, route_map, route_map_dn ]
      rp_updates:
        description:
        - The control state of the Bootstrap Router (BSR) policy.
        - Specify C([]) to remove the control state configuration.
        type: list
        elements: str
        aliases: [ control, ctrl ]
        choices: [ forward, listen ]
  auto_rp:
    description: Configuration container for Protocol Independent Multicast (PIM) Auto-Rendezvous Point (Auto-RP) settings.
    type: dict
    aliases: [ auto ]
    suboptions:
      ma_filter:
        description:
        - The DN of the Route Map.
        - Specify C("") to remove the Route Map configuration.
        type: str
        aliases: [ filter, route_map, route_map_dn ]
      rp_updates:
        description:
        - The control state of the Auto-Rendezvous Point (Auto-RP) policy.
        - Specify C([]) to remove the control state configuration.
        type: list
        elements: str
        aliases: [ control, ctrl ]
        choices: [ forward, listen ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- The I(tenant) and I(vrf) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_vrf) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(pim:CtxP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Enable Multicast on a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
    state: present
  delegate_to: localhost

- name: Change Multicast PIM Settings on a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
    pim_setting:
      mtu: 2000
      control_state: [fast, strict]
    state: present
  delegate_to: localhost

- name: Change Multicast Resource Policy on a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
    resource_policy:
      maximum_limit: 100
      reserved_multicast_entries: 20
      reserved_route_map: uni/tn-ansible_test/rtmap-ansible_test
    state: present
  delegate_to: localhost

- name: Remove Route-Map from Multicast Resource Policy on a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
    resource_policy:
      reserved_route_map: ""
    state: present
  delegate_to: localhost

- name: Change Multicast Any Source Multicast (ASM) Settings on a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
    any_source_multicast:
      shared_range_route_map: uni/tn-ansible_test/rtmap-ansible_test
      source_group_expiry_route_map: uni/tn-ansible_test/rtmap-ansible_test
      expiry: 500
      max_rate: 64000
      source_ip: 1.1.1.1
    state: present
  delegate_to: localhost

- name: Change Multicast Source Specific Multicast (SSM) Settings on a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
    source_specific_multicast:
      group_range_route_map: uni/tn-ansible_test/rtmap-ansible_test
    state: present
  delegate_to: localhost

- name: Change Multicast Bootstrap Router (BSR) Settings on a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
    bootstrap_router:
      bsr_filter: uni/tn-ansible_test/rtmap-ansible_test
      rp_updates: [forward, listen]
    state: present
  delegate_to: localhost

- name: Change Multicast Auto-Rendezvous Point (Auto-RP) Settings on a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
    auto_rp:
      ma_filter: uni/tn-ansible_test/rtmap-ansible_test
      rp_updates: [forward, listen]
    state: present
  delegate_to: localhost

- name: Disable Multicast on a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
    state: absent
  delegate_to: localhost

- name: Query Multicast Settings for a VRF
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: ansible_tenant
    vrf: ansible_vrf
    state: query
  delegate_to: localhost
  register: query_result

- name: Query Multicast Settings for all VRFs
  cisco.aci.aci_vrf_multicast:
    host: apic
    username: admin
    password: SomeSecretePassword
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = r"""
   current:
     description: The existing configuration from the APIC after the module has finished
     returned: success
     type: list
     sample:
       [
           {
               "fvTenant": {
                   "attributes": {
                       "descr": "Production environment",
                       "dn": "uni/tn-production",
                       "name": "production",
                       "nameAlias": "",
                       "ownerKey": "",
                       "ownerTag": ""
                   }
               }
           }
       ]
   error:
     description: The error information as returned from the APIC
     returned: failure
     type: dict
     sample:
       {
           "code": "122",
           "text": "unknown managed object class foo"
       }
   raw:
     description: The raw output returned by the APIC REST API (xml or json)
     returned: parse error
     type: str
     sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class "/></imdata>'
   sent:
     description: The actual/minimal configuration pushed to the APIC
     returned: info
     type: list
     sample:
       {
           "fvTenant": {
               "attributes": {
                   "descr": "Production environment"
               }
           }
       }
   previous:
     description: The original configuration from the APIC before the module has started
     returned: info
     type: list
     sample:
       [
           {
               "fvTenant": {
                   "attributes": {
                       "descr": "Production",
                       "dn": "uni/tn-production",
                       "name": "production",
                       "nameAlias": "",
                       "ownerKey": "",
                       "ownerTag": ""
                   }
               }
           }
       ]
   proposed:
     description: The assembled configuration from the user-provided parameters
     returned: info
     type: dict
     sample:
       {
           "fvTenant": {
               "attributes": {
                   "descr": "Production environment",
                   "name": "production"
               }
           }
       }
   filter_string:
     description: The filter string used for the request
     returned: failure or debug
     type: str
     sample: ?rsp-prop-include=config-only
   method:
     description: The HTTP method used for the request to the APIC
     returned: failure or debug
     type: str
     sample: POST
   response:
     description: The HTTP response from the APIC
     returned: failure or debug
     type: str
     sample: OK (30 bytes)
   status:
     description: The HTTP status from the APIC
     returned: failure or debug
     type: int
     sample: 200
   url:
     description: The HTTP url used for the request to the APIC
     returned: failure or debug
     type: str
     sample: https://10.11.12.13/api/mo/uni/tn-production.json
   """

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible_collections.cisco.aci.plugins.module_utils.constants import PIM_SETTING_CONTROL_STATE_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        vrf=dict(type="str", aliases=["vrf_name"]),
        pim_setting=dict(
            type="dict",
            options=dict(
                mtu=dict(type="int"),
                control_state=dict(type="list", elements="str", choices=["fast", "strict"], aliases=["control", "ctrl"]),
            ),
        ),
        resource_policy=dict(
            type="dict",
            options=dict(
                maximum_limit=dict(type="int", aliases=["max"]),
                reserved_multicast_entries=dict(type="int", aliases=["rsvd"]),
                reserved_route_map=dict(type="str", aliases=["route_map", "route_map_dn"]),
            ),
        ),
        any_source_multicast=dict(
            type="dict",
            options=dict(
                shared_range_route_map=dict(type="str", aliases=["shared_range_policy"]),
                source_group_expiry_route_map=dict(type="str", aliases=["sg_expiry_route_map"]),
                expiry=(dict(type="int", aliases=["expiry_seconds"])),
                max_rate=(dict(type="int", aliases=["max_rate_per_second"])),
                source_ip=(dict(type="str", aliases=["source", "source_ip_address"])),
            ),
            aliases=["asm", "any_source"],
        ),
        source_specific_multicast=dict(
            type="dict",
            options=dict(
                group_range_route_map=dict(type="str", aliases=["group_range_policy"]),
            ),
            aliases=["ssm", "specific_source"],
        ),
        bootstrap_router=dict(
            type="dict",
            options=dict(
                bsr_filter=dict(type="str", aliases=["filter", "route_map", "route_map_dn"]),
                rp_updates=dict(type="list", elements="str", choices=["forward", "listen"], aliases=["control", "ctrl"]),
            ),
            aliases=["bsr", "bootstrap"],
        ),
        auto_rp=dict(
            type="dict",
            options=dict(
                ma_filter=dict(type="str", aliases=["filter", "route_map", "route_map_dn"]),
                rp_updates=dict(type="list", elements="str", choices=["forward", "listen"], aliases=["control", "ctrl"]),
            ),
            aliases=["auto"],
        ),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "vrf"]],
            ["state", "present", ["tenant", "vrf"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    vrf = module.params.get("vrf")
    pim_setting = module.params.get("pim_setting")
    resource_policy = module.params.get("resource_policy")
    any_source_multicast = module.params.get("any_source_multicast")
    source_specific_multicast = module.params.get("source_specific_multicast")
    bootstrap_router = module.params.get("bootstrap_router")
    auto_rp = module.params.get("auto_rp")
    state = module.params.get("state")

    if resource_policy and resource_policy.get("reserved_multicast_entries") and resource_policy.get("reserved_route_map") is None:
        aci.fail_json(msg="C(reserved_route_map) must be provided when C(reserved_multicast_entries) are provided")
    elif resource_policy and resource_policy.get("reserved_route_map") and not resource_policy.get("reserved_multicast_entries"):
        aci.fail_json(msg="C(reserved_multicast_entries) must be provided and greater than 0 when C(reserved_route_map) is provided")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvCtx",
            aci_rn="ctx-{0}".format(vrf),
            module_object=vrf,
            target_filter={"name": vrf},
        ),
        subclass_2=dict(
            aci_class="pimCtxP",
            aci_rn="pimctxp",
            target_filter={"name": ""},
        ),
        child_classes=["pimResPol", "pimASMPatPol", "pimSSMPatPol", "pimAutoRPPol", "pimBSRPPol"],
    )

    aci.get_existing()

    if state == "present":
        existing_config = aci.existing[0] if aci.existing else {}
        child_configs = []

        resource_policy_config = dict(pimResPol=dict(attributes=dict(name=""), children=[]))
        if resource_policy:
            max = "unlimited" if resource_policy.get("maximum_limit") == 0 else resource_policy.get("maximum_limit")
            if max is not None:
                resource_policy_config["pimResPol"]["attributes"]["max"] = str(max)

            reserved_route_map = resource_policy.get("reserved_route_map")
            if reserved_route_map is not None:
                existing_rrm = get_child_from_existing_config(existing_config, ["pimCtxP", "pimResPol", "rtdmcRsFilterToRtMapPol"])
                rsvd = resource_policy.get("reserved_multicast_entries")

                if (existing_rrm or reserved_route_map != "") and rsvd:
                    resource_policy_config["pimResPol"]["attributes"]["rsvd"] = str(rsvd)
                elif existing_rrm and reserved_route_map == "":
                    resource_policy_config["pimResPol"]["attributes"]["rsvd"] = "undefined"

                set_route_map_config(
                    existing_config,
                    resource_policy_config["pimResPol"]["children"],
                    ["pimCtxP", "pimResPol", "rtdmcRsFilterToRtMapPol"],
                    reserved_route_map,
                )

        child_configs.append(resource_policy_config)

        any_source_multicast_config = dict(
            pimASMPatPol=dict(
                attributes=dict(name=""),
                children=[
                    dict(pimSharedRangePol=dict(attributes=dict(name=""), children=[])),
                    dict(pimSGRangeExpPol=dict(attributes=dict(name=""), children=[])),
                    dict(pimRegTrPol=dict(attributes=dict(name=""), children=[])),
                ],
            )
        )
        if any_source_multicast:
            if any_source_multicast.get("shared_range_route_map") is not None:
                set_route_map_config(
                    existing_config,
                    any_source_multicast_config["pimASMPatPol"]["children"][0]["pimSharedRangePol"]["children"],
                    ["pimCtxP", "pimASMPatPol", "pimSharedRangePol", "rtdmcRsFilterToRtMapPol"],
                    any_source_multicast.get("shared_range_route_map"),
                )

            if any_source_multicast.get("source_group_expiry_route_map") is not None:
                set_route_map_config(
                    existing_config,
                    any_source_multicast_config["pimASMPatPol"]["children"][1]["pimSGRangeExpPol"]["children"],
                    ["pimCtxP", "pimASMPatPol", "pimSGRangeExpPol", "rtdmcRsFilterToRtMapPol"],
                    any_source_multicast.get("source_group_expiry_route_map"),
                )

            expiry = any_source_multicast.get("expiry")
            if expiry is not None:
                sg_expiry_config = "default-timeout" if any_source_multicast.get("expiry") == 0 else any_source_multicast.get("expiry")
                any_source_multicast_config["pimASMPatPol"]["children"][1]["pimSGRangeExpPol"]["attributes"]["sgExpItvl"] = str(sg_expiry_config)

            if any_source_multicast.get("max_rate") is not None:
                any_source_multicast_config["pimASMPatPol"]["children"][2]["pimRegTrPol"]["attributes"]["maxRate"] = str(any_source_multicast.get("max_rate"))

            if any_source_multicast.get("source_ip") is not None:
                any_source_multicast_config["pimASMPatPol"]["children"][2]["pimRegTrPol"]["attributes"]["srcIp"] = any_source_multicast.get("source_ip")

        child_configs.append(any_source_multicast_config)

        source_specific_multicast_config = dict(
            pimSSMPatPol=dict(
                attributes=dict(name=""),
                children=[
                    dict(pimSSMRangePol=dict(attributes=dict(name=""), children=[])),
                ],
            )
        )
        if source_specific_multicast and source_specific_multicast.get("group_range_route_map") is not None:
            set_route_map_config(
                existing_config,
                source_specific_multicast_config["pimSSMPatPol"]["children"][0]["pimSSMRangePol"]["children"],
                ["pimCtxP", "pimSSMPatPol", "pimSSMRangePol", "rtdmcRsFilterToRtMapPol"],
                source_specific_multicast.get("group_range_route_map"),
            )

        child_configs.append(source_specific_multicast_config)

        if bootstrap_router:
            bsr_config = dict(pimBSRPPol=dict(attributes=dict(name=""), children=[dict(pimBSRFilterPol=dict(attributes=dict(name=""), children=[]))]))
            if bootstrap_router.get("bsr_filter") is not None:
                set_route_map_config(
                    existing_config,
                    bsr_config["pimBSRPPol"]["children"][0]["pimBSRFilterPol"]["children"],
                    ["pimCtxP", "pimBSRPPol", "pimBSRFilterPol", "rtdmcRsFilterToRtMapPol"],
                    bootstrap_router.get("bsr_filter"),
                )

            rp_updates = bootstrap_router.get("rp_updates")
            if rp_updates is not None:
                bsr_config["pimBSRPPol"]["attributes"]["ctrl"] = ",".join(sorted(rp_updates))

            child_configs.append(bsr_config)

        if auto_rp:
            auto_rp_config = dict(pimAutoRPPol=dict(attributes=dict(name=""), children=[dict(pimMAFilterPol=dict(attributes=dict(name=""), children=[]))]))

            if auto_rp.get("ma_filter") is not None:
                set_route_map_config(
                    existing_config,
                    auto_rp_config["pimAutoRPPol"]["children"][0]["pimMAFilterPol"]["children"],
                    ["pimCtxP", "pimAutoRPPol", "pimMAFilterPol", "rtdmcRsFilterToRtMapPol"],
                    auto_rp.get("ma_filter"),
                )

            rp_updates = auto_rp.get("rp_updates")
            if rp_updates is not None:
                auto_rp_config["pimAutoRPPol"]["attributes"]["ctrl"] = ",".join(sorted(rp_updates))

            child_configs.append(auto_rp_config)

        mtu = None
        control_state = None
        if pim_setting:
            mtu = pim_setting.get("mtu")
            control_state = (
                ",".join(sorted([PIM_SETTING_CONTROL_STATE_MAPPING.get(v) for v in pim_setting.get("control_state")]))
                if pim_setting.get("control_state") is not None
                else None
            )

        aci.payload(
            aci_class="pimCtxP",
            class_config=dict(mtu=mtu, ctrl=control_state),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="pimCtxP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


def get_child_from_existing_config(config, class_names):
    parent = class_names[0]
    class_names.remove(parent)

    for child in config.get(parent, {}).get("children", []):
        if len(class_names) == 1 and class_names[0] in child.keys():
            return child
        elif child.get(class_names[0], {}).get("children"):
            return get_child_from_existing_config(child, class_names)


def set_route_map_config(existing_config, new_config, class_names, route_map):
    existing_route_map = get_child_from_existing_config(existing_config, class_names)
    if route_map == "" and existing_route_map:
        new_config.append(dict(rtdmcRsFilterToRtMapPol=dict(attributes=dict(tDn=route_map, status="deleted"))))
    elif route_map:
        new_config.append(dict(rtdmcRsFilterToRtMapPol=dict(attributes=dict(tDn=route_map))))


if __name__ == "__main__":
    main()
