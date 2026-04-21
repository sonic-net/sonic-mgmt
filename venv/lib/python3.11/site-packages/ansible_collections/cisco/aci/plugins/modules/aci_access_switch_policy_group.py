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
module: aci_access_switch_policy_group
short_description: Manage Access Switch Policy Groups (infra:AccNodePGrp and infra:SpineAccNodePGrp).
description:
- Manage Access Switch Policy Groups on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the access switch policy group.
    aliases: [ policy_group ]
    type: str
  description:
    description:
    - The description of the access switch policy group.
    type: str
  switch_type:
    description:
    - Whether this is a leaf or spine policy group
    type: str
    choices: [ leaf, spine ]
    required: true
  spanning_tree_policy:
    description:
    - The spanning tree policy bound to the access switch policy group.
    - Only available in APIC version 5.2 or later.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  bfd_ipv4_policy:
    description:
    - The BFD IPv4 policy bound to the access switch policy group.
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  bfd_ipv6_policy:
    description:
    - The BFD IPv6 policy bound to the access switch policy group.
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  bfd_multihop_ipv4_policy:
    description:
    - The BFD multihop IPv4 policy bound to the access switch policy group.
    - Only available in APIC version 5.x or later.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  bfd_multihop_ipv6_policy:
    description:
    - The BFD multihop IPv6 policy bound to the access switch policy group.
    - Only available in APIC version 5.x or later.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  fibre_channel_node_policy:
    description:
    - The fibre channel node policy bound to the access switch policy group.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  poe_node_policy:
    description:
    - The PoE node policy bound to the access switch policy group.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  fibre_channel_san_policy:
    description:
    - The fibre channel SAN policy bound to the access switch policy group.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  monitoring_policy:
    description:
    - The monitoring policy bound to the access switch policy group.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  netflow_node_policy:
    description:
    - The netflow node policy bound to the access switch policy group.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  copp_policy:
    description:
    - The CoPP policy bound to the access switch policy group.
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  forward_scale_profile_policy:
    description:
    - The forward scale profile policy bound to the access switch policy group.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  fast_link_failover_policy:
    description:
    - The fast link failover policy bound to the access switch policy group.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  node_802_1x_authentication_policy:
    description:
    - The 802.1x node authentication policy bound to the access switch policy group.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  copp_pre_filter_policy:
    description:
    - The CoPP pre-filter policy bound to the access switch policy group.
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  equipment_flash_policy:
    description:
    - The equipment flash policy bound to the access switch policy group.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  cdp_policy:
    description:
    - The CDP policy bound to the access switch policy group.
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  lldp_policy:
    description:
    - The LLDP policy bound to the access switch policy group.
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  sync_e_node_policy:
    description:
    - The SyncE node policy bound to the access switch policy group.
    - Only available in APIC version 5.x or later.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  ptp_node_policy:
    description:
    - The PTP node policy bound to the access switch policy group.
    - Only available in APIC version 5.2 or later.
    - Only available when I(switch_type=leaf).
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
  usb_configuration_policy:
    description:
    - The USB configuration policy bound to the access switch policy group.
    - Only available in APIC version 5.2 or later.
    - The APIC defaults to C("") which results in the target DN set to the default policy when unset during creation.
    type: str
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(infra:AccNodePGrp) and B(infra:SpineAccNodePGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Create Leaf Access Switch Policy Group
  cisco.aci.aci_access_switch_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ansible_pol_grp_spine
    switch_type: leaf
    spanning_tree_policy: example_spanning_tree_policy
    bfd_ipv4_policy: example_bfd_ipv4_policy
    bfd_ipv6_policy: example_bfd_ipv6_policy
    fibre_channel_node_policy: example_fibre_channel_node_policy
    poe_node_policy: example_poe_node_policy
    fibre_channel_san_policy: example_fibre_channel_san_policy
    monitoring_policy: example_monitoring_policy
    copp_policy: example_copp_policy
    forward_scale_profile_policy: example_forward_scale_profile_policy
    fast_link_failover_policy: example_fast_link_failover_policy
    node_802_1x_authentication_policy: example_node_802_1x_authentication_policy
    copp_pre_filter_policy: example_copp_pre_filter_policy
    equipment_flash_policy: example_equipment_flash_policy
    cdp_policy: example_cdp_policy
    lldp_policy: example_lldp_policy
    state: present
  delegate_to: localhost

- name: Create Spine Access Switch Policy Group
  cisco.aci.aci_access_switch_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ansible_pol_grp_leaf
    switch_type: spine
    bfd_ipv4_policy: example_bfd_ipv4_policy
    bfd_ipv6_policy: example_bfd_ipv6_policy
    copp_policy: example_copp_policy
    copp_pre_filter_policy: example_copp_pre_filter_policy
    cdp_policy: example_cdp_policy
    lldp_policy: example_lldp_policy
    state: present
  delegate_to: localhost

- name: Delete Leaf Access Switch Policy Group
  cisco.aci.aci_access_switch_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ansible_pol_grp_leaf
    switch_type: leaf
    state: absent
  delegate_to: localhost

- name: Query Leaf Access Switch Policy Group
  cisco.aci.aci_access_switch_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ansible_pol_grp_leaf
    switch_type: leaf
    state: query
  delegate_to: localhost
  register: query_result

- name: Query All Leaf Access Switch Policy Groups
  cisco.aci.aci_access_switch_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_type: leaf
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["policy_group"]),
        description=dict(type="str"),
        switch_type=dict(type="str", choices=["leaf", "spine"], required=True),
        spanning_tree_policy=dict(type="str"),
        bfd_ipv4_policy=dict(type="str"),
        bfd_ipv6_policy=dict(type="str"),
        bfd_multihop_ipv4_policy=dict(type="str"),
        bfd_multihop_ipv6_policy=dict(type="str"),
        fibre_channel_node_policy=dict(type="str"),
        poe_node_policy=dict(type="str"),
        fibre_channel_san_policy=dict(type="str"),
        monitoring_policy=dict(type="str"),
        netflow_node_policy=dict(type="str"),
        copp_policy=dict(type="str"),
        forward_scale_profile_policy=dict(type="str"),
        fast_link_failover_policy=dict(type="str"),
        node_802_1x_authentication_policy=dict(type="str"),
        copp_pre_filter_policy=dict(type="str"),
        equipment_flash_policy=dict(type="str"),
        cdp_policy=dict(type="str"),
        lldp_policy=dict(type="str"),
        sync_e_node_policy=dict(type="str"),
        ptp_node_policy=dict(type="str"),
        usb_configuration_policy=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
    )
    name = module.params.get("name")
    description = module.params.get("description")
    switch_type = module.params.get("switch_type")
    spanning_tree_policy = module.params.get("spanning_tree_policy")
    bfd_ipv4_policy = module.params.get("bfd_ipv4_policy")
    bfd_ipv6_policy = module.params.get("bfd_ipv6_policy")
    bfd_multihop_ipv4_policy = module.params.get("bfd_multihop_ipv4_policy")
    bfd_multihop_ipv6_policy = module.params.get("bfd_multihop_ipv6_policy")
    fibre_channel_node_policy = module.params.get("fibre_channel_node_policy")
    poe_node_policy = module.params.get("poe_node_policy")
    fibre_channel_san_policy = module.params.get("fibre_channel_san_policy")
    monitoring_policy = module.params.get("monitoring_policy")
    netflow_node_policy = module.params.get("netflow_node_policy")
    copp_policy = module.params.get("copp_policy")
    forward_scale_profile_policy = module.params.get("forward_scale_profile_policy")
    fast_link_failover_policy = module.params.get("fast_link_failover_policy")
    node_802_1x_authentication_policy = module.params.get("node_802_1x_authentication_policy")
    copp_pre_filter_policy = module.params.get("copp_pre_filter_policy")
    equipment_flash_policy = module.params.get("equipment_flash_policy")
    cdp_policy = module.params.get("cdp_policy")
    lldp_policy = module.params.get("lldp_policy")
    sync_e_node_policy = module.params.get("sync_e_node_policy")
    ptp_node_policy = module.params.get("ptp_node_policy")
    usb_configuration_policy = module.params.get("usb_configuration_policy")
    state = module.params.get("state")

    aci = ACIModule(module)

    if switch_type == "spine" and not all(
        v is None
        for v in [
            spanning_tree_policy,
            bfd_multihop_ipv4_policy,
            bfd_multihop_ipv6_policy,
            fibre_channel_node_policy,
            poe_node_policy,
            fibre_channel_san_policy,
            monitoring_policy,
            netflow_node_policy,
            forward_scale_profile_policy,
            fast_link_failover_policy,
            node_802_1x_authentication_policy,
            equipment_flash_policy,
            sync_e_node_policy,
            ptp_node_policy,
        ]
    ):
        aci.fail_json(msg="Unsupported policy provided for spine switch type.")

    class_name = ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type).get("class_name")

    aci.construct_url(
        root_class=dict(
            aci_class=class_name,
            aci_rn=ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type).get("rn").format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        rsp_subtree="children",
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if forward_scale_profile_policy is not None:
            child_configs.append({"infraRsTopoctrlFwdScaleProfPol": {"attributes": {"tnTopoctrlFwdScaleProfilePolName": forward_scale_profile_policy}}})
        if usb_configuration_policy is not None:
            child_configs.append(
                {
                    ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type)
                    .get("usb_configuration_policy")
                    .get("class_name"): {
                        "attributes": {
                            ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type)
                            .get("usb_configuration_policy")
                            .get("tn_name"): usb_configuration_policy
                        }
                    }
                }
            )
        if lldp_policy is not None:
            child_configs.append(
                {
                    ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type)
                    .get("lldp_policy")
                    .get("class_name"): {
                        "attributes": {ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type).get("lldp_policy").get("tn_name"): lldp_policy}
                    }
                }
            )
        if cdp_policy is not None:
            child_configs.append(
                {
                    ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type)
                    .get("cdp_policy")
                    .get("class_name"): {
                        "attributes": {ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type).get("cdp_policy").get("tn_name"): cdp_policy}
                    }
                }
            )
        if bfd_ipv4_policy is not None:
            child_configs.append(
                {
                    ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type)
                    .get("bfd_ipv4_policy")
                    .get("class_name"): {
                        "attributes": {ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type).get("bfd_ipv4_policy").get("tn_name"): bfd_ipv4_policy}
                    }
                }
            )
        if bfd_ipv6_policy is not None:
            child_configs.append(
                {
                    ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type)
                    .get("bfd_ipv6_policy")
                    .get("class_name"): {
                        "attributes": {ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type).get("bfd_ipv6_policy").get("tn_name"): bfd_ipv6_policy}
                    }
                }
            )
        if sync_e_node_policy is not None:
            child_configs.append({"infraRsSynceInstPol": {"attributes": {"tnSynceInstPolName": sync_e_node_policy}}})
        if poe_node_policy is not None:
            child_configs.append({"infraRsPoeInstPol": {"attributes": {"tnPoeInstPolName": poe_node_policy}}})
        if bfd_multihop_ipv4_policy is not None:
            child_configs.append({"infraRsBfdMhIpv4InstPol": {"attributes": {"tnBfdMhIpv4InstPolName": bfd_multihop_ipv4_policy}}})
        if bfd_multihop_ipv6_policy is not None:
            child_configs.append({"infraRsBfdMhIpv6InstPol": {"attributes": {"tnBfdMhIpv6InstPolName": bfd_multihop_ipv6_policy}}})
        if equipment_flash_policy is not None:
            child_configs.append({"infraRsEquipmentFlashConfigPol": {"attributes": {"tnEquipmentFlashConfigPolName": equipment_flash_policy}}})
        if monitoring_policy is not None:
            child_configs.append({"infraRsMonNodeInfraPol": {"attributes": {"tnMonInfraPolName": monitoring_policy}}})
        if fibre_channel_node_policy is not None:
            child_configs.append({"infraRsFcInstPol": {"attributes": {"tnFcInstPolName": fibre_channel_node_policy}}})
        if fast_link_failover_policy is not None:
            child_configs.append(
                {"infraRsTopoctrlFastLinkFailoverInstPol": {"attributes": {"tnTopoctrlFastLinkFailoverInstPolName": fast_link_failover_policy}}}
            )
        if spanning_tree_policy is not None:
            child_configs.append({"infraRsMstInstPol": {"attributes": {"tnStpInstPolName": spanning_tree_policy}}})
        if fibre_channel_san_policy is not None:
            child_configs.append({"infraRsFcFabricPol": {"attributes": {"tnFcFabricPolName": fibre_channel_san_policy}}})
        if copp_policy is not None:
            child_configs.append(
                {
                    ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type)
                    .get("copp_policy")
                    .get("class_name"): {
                        "attributes": {ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type).get("copp_policy").get("tn_name"): copp_policy}
                    }
                }
            )
        if node_802_1x_authentication_policy is not None:
            child_configs.append({"infraRsL2NodeAuthPol": {"attributes": {"tnL2NodeAuthPolName": node_802_1x_authentication_policy}}})
        if copp_pre_filter_policy is not None:
            child_configs.append(
                {
                    ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type)
                    .get("copp_pre_filter_policy")
                    .get("class_name"): {
                        "attributes": {
                            ACI_ACCESS_SWITCH_POLICY_GROUP_CLASS_MAPPING.get(switch_type).get("copp_pre_filter_policy").get("tn_name"): copp_pre_filter_policy
                        }
                    }
                }
            )
        if netflow_node_policy is not None:
            child_configs.append({"infraRsNetflowNodePol": {"attributes": {"tnNetflowNodePolName": netflow_node_policy}}})
        if ptp_node_policy is not None:
            child_configs.append({"infraRsPtpInstPol": {"attributes": {"tnPtpInstPolName": ptp_node_policy}}})

        if child_configs == []:
            child_configs = None

        aci.payload(
            aci_class=class_name,
            class_config=dict(
                descr=description,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class=class_name)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
