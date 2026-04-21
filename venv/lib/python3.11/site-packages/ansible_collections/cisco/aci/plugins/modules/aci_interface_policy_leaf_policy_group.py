#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Bruno Calogero <brunocalogero@hotmail.com>
# Copyright: (c) 2023, Anvitha Jain <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_leaf_policy_group
short_description: Manage fabric interface policy leaf policy groups (infra:AccBndlGrp and infra:AccPortGrp)
description:
- Manage fabric interface policy leaf policy groups on Cisco ACI fabrics.
options:
  policy_group:
    description:
    - The name of the leaf interface policy group.
    type: str
    aliases: [ name, policy_group_name ]
  description:
    description:
    - The description of the leaf interface policy group.
    type: str
    aliases: [ descr ]
  lag_type:
    description:
    - Selector for the type of leaf interface policy group.
    - C(leaf) for Leaf Access Port Policy Group
    - C(link) for Port Channel (PC)
    - C(node) for Virtual Port Channel (VPC)
    type: str
    required: true
    choices: [ leaf, link, node ]
    aliases: [ lag_type_name ]
  link_level_policy:
    description:
    - The name of the link level policy used by the leaf interface policy group.
    type: str
    aliases: [ link_level_policy_name ]
  cdp_policy:
    description:
    - The name of the cdp policy used by the leaf interface policy group.
    type: str
    aliases: [ cdp_policy_name ]
  mcp_policy:
    description:
    - The name of the mcp policy used by the leaf interface policy group.
    type: str
    aliases: [ mcp_policy_name ]
  lldp_policy:
    description:
    - The name of the lldp policy used by the leaf interface policy group.
    type: str
    aliases: [ lldp_policy_name ]
  stp_interface_policy:
    description:
    - The name of the stp interface policy used by the leaf interface policy group.
    type: str
    aliases: [ stp_interface_policy_name ]
  egress_data_plane_policing_policy:
    description:
    - The name of the egress data plane policing policy used by the leaf interface policy group.
    type: str
    aliases: [ egress_data_plane_policing_policy_name ]
  ingress_data_plane_policing_policy:
    description:
    - The name of the ingress data plane policing policy used by the leaf interface policy group.
    type: str
    aliases: [ ingress_data_plane_policing_policy_name ]
  priority_flow_control_policy:
    description:
    - The name of the priority flow control policy used by the leaf interface policy group.
    type: str
    aliases: [ priority_flow_control_policy_name ]
  fibre_channel_interface_policy:
    description:
    - The name of the fibre channel interface policy used by the leaf interface policy group.
    type: str
    aliases: [ fibre_channel_interface_policy_name ]
  slow_drain_policy:
    description:
    - The name of the slow drain policy used by the leaf interface policy group.
    type: str
    aliases: [ slow_drain_policy_name ]
  port_channel_policy:
    description:
    - The name of the port channel policy used by the leaf interface policy group.
    type: str
    aliases: [ port_channel_policy_name ]
  monitoring_policy:
    description:
    - The name of the monitoring policy used by the leaf interface policy group.
    type: str
    aliases: [ monitoring_policy_name ]
  storm_control_interface_policy:
    description:
    - The name of the storm control interface policy used by the leaf interface policy group.
    type: str
    aliases: [ storm_control_interface_policy_name ]
  l2_interface_policy:
    description:
    - The name of the l2 interface policy used by the leaf interface policy group.
    type: str
    aliases: [ l2_interface_policy_name ]
  port_security_policy:
    description:
    - The name of the port security policy used by the leaf interface policy group.
    type: str
    aliases: [ port_security_policy_name ]
  link_flap_policy:
    description:
    - The name of the link flap policy used by the leaf interface policy group.
    type: str
    aliases: [ link_flap_policy_name ]
  link_level_flow_control:
    description:
    - The name of the link level flow control used by the leaf interface policy group.
    type: str
    aliases: [ link_level_flow_control_name ]
  mac_sec_interface_policy:
    description:
    - The name of the mac sec interface policy used by the leaf interface policy group.
    type: str
    aliases: [ mac_sec_interface_policy_name ]
  copp_policy:
    description:
    - The name of the copp policy used by the leaf interface policy group.
    type: str
    aliases: [ copp_policy_name ]
  sync_e_interface_policy:
    description:
    - The name of the syncE interface policy used by the leaf interface policy group.
    - Only availavle in APIC version 5.2 or later.
    type: str
    aliases: [ sync_e_interface_policy_name ]
  port_authentication:
    description:
    - The name of the port authentication used by the leaf interface policy group.
    type: str
    aliases: [ port_authentication_name ]
  dwdm:
    description:
    - The name of the dwdm used by the leaf interface policy group.
    type: str
    aliases: [ dwdm_name ]
  poe_interface_policy:
    description:
    - The name of the poe interface policy used by the leaf interface policy group.
    type: str
    aliases: [ poe_interface_policy_name ]
  transceiver_policy:
    description:
    - The name of the transceiver policy used by the leaf interface policy group.
    - Only availavle in APIC version 6.0(2h) or later.
    type: dict
    suboptions:
      type:
        description:
        - The type of the transceiver policy.
        type: str
        required: true
        aliases: [ transceiver_policy_type ]
        choices: [ zr, zrp]
      name:
        description:
        - The name of the transceiver policy.
        type: str
        required: true
        aliases: [ transceiver_policy_name ]
  aep:
    description:
    - The name of the attached entity profile (AEP) used by the leaf interface policy group.
    type: str
    aliases: [ aep_name ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- When using the module please select the appropriate link_aggregation_type (lag_type).
- C(link) for Port Channel(PC), C(node) for Virtual Port Channel(VPC) and C(leaf) for Leaf Access Port Policy Group.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:AccBndlGrp) and B(infra:AccPortGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Bruno Calogero (@brunocalogero)
"""

EXAMPLES = r"""
- name: Create a Port Channel (PC) Interface Policy Group
  cisco.aci.aci_interface_policy_leaf_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: link
    policy_group: policygroupname
    description: policygroupname description
    link_level_policy: linklevelpolicy
    cdp_policy: cdppolicy
    lldp_policy: lldppolicy
    port_channel_policy: lacppolicy
    state: present
  delegate_to: localhost

- name: Create a Virtual Port Channel (VPC) Interface Policy Group
  cisco.aci.aci_interface_policy_leaf_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: node
    policy_group: policygroupname
    link_level_policy: linklevelpolicy
    cdp_policy: cdppolicy
    lldp_policy: lldppolicy
    port_channel_policy: lacppolicy
    state: present
  delegate_to: localhost

- name: Create a Leaf Access Port Policy Group
  cisco.aci.aci_interface_policy_leaf_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: leaf
    policy_group: policygroupname
    link_level_policy: linklevelpolicy
    cdp_policy: cdppolicy
    lldp_policy: lldppolicy
    state: present
  delegate_to: localhost

- name: Query all Leaf Access Port Policy Groups of type link
  cisco.aci.aci_interface_policy_leaf_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: link
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific Lead Access Port Policy Group
  cisco.aci.aci_interface_policy_leaf_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: leaf
    policy_group: policygroupname
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete an Interface policy Leaf Policy Group
  cisco.aci.aci_interface_policy_leaf_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    lag_type: leaf
    policy_group: policygroupname
    state: absent
  delegate_to: localhost
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
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
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


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        # NOTE: Since this module needs to include both infra:AccBndlGrp (for PC and VPC) and infra:AccPortGrp (for leaf access port policy group):
        # NOTE: The user(s) can make the choice between (link(PC), node(VPC), leaf(leaf-access port policy group))
        lag_type=dict(type="str", required=True, aliases=["lag_type_name"], choices=["leaf", "link", "node"]),
        policy_group=dict(type="str", aliases=["name", "policy_group_name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        link_level_policy=dict(type="str", aliases=["link_level_policy_name"]),
        cdp_policy=dict(type="str", aliases=["cdp_policy_name"]),
        mcp_policy=dict(type="str", aliases=["mcp_policy_name"]),
        lldp_policy=dict(type="str", aliases=["lldp_policy_name"]),
        stp_interface_policy=dict(type="str", aliases=["stp_interface_policy_name"]),
        egress_data_plane_policing_policy=dict(type="str", aliases=["egress_data_plane_policing_policy_name"]),
        ingress_data_plane_policing_policy=dict(type="str", aliases=["ingress_data_plane_policing_policy_name"]),
        priority_flow_control_policy=dict(type="str", aliases=["priority_flow_control_policy_name"]),
        fibre_channel_interface_policy=dict(type="str", aliases=["fibre_channel_interface_policy_name"]),
        slow_drain_policy=dict(type="str", aliases=["slow_drain_policy_name"]),
        port_channel_policy=dict(type="str", aliases=["port_channel_policy_name"]),
        monitoring_policy=dict(type="str", aliases=["monitoring_policy_name"]),
        storm_control_interface_policy=dict(type="str", aliases=["storm_control_interface_policy_name"]),
        l2_interface_policy=dict(type="str", aliases=["l2_interface_policy_name"]),
        port_security_policy=dict(type="str", aliases=["port_security_policy_name"]),
        link_flap_policy=dict(type="str", aliases=["link_flap_policy_name"]),
        link_level_flow_control=dict(type="str", aliases=["link_level_flow_control_name"]),
        mac_sec_interface_policy=dict(type="str", aliases=["mac_sec_interface_policy_name"]),
        copp_policy=dict(type="str", aliases=["copp_policy_name"]),
        aep=dict(type="str", aliases=["aep_name"]),
        sync_e_interface_policy=dict(type="str", aliases=["sync_e_interface_policy_name"]),
        transceiver_policy=dict(
            type="dict",
            options=dict(
                name=dict(type="str", required=True, aliases=["transceiver_policy_name"]),
                type=dict(type="str", required=True, choices=["zr", "zrp"], aliases=["transceiver_policy_type"]),
            ),
        ),
        poe_interface_policy=dict(type="str", aliases=["poe_interface_policy_name"]),
        port_authentication=dict(type="str", aliases=["port_authentication_name"]),
        dwdm=dict(type="str", aliases=["dwdm_name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["policy_group"]],
            ["state", "present", ["policy_group"]],
        ],
    )

    policy_group = module.params.get("policy_group")
    description = module.params.get("description")
    lag_type = module.params.get("lag_type")
    link_level_policy = module.params.get("link_level_policy")
    cdp_policy = module.params.get("cdp_policy")
    mcp_policy = module.params.get("mcp_policy")
    lldp_policy = module.params.get("lldp_policy")
    stp_interface_policy = module.params.get("stp_interface_policy")
    egress_data_plane_policing_policy = module.params.get("egress_data_plane_policing_policy")
    ingress_data_plane_policing_policy = module.params.get("ingress_data_plane_policing_policy")
    priority_flow_control_policy = module.params.get("priority_flow_control_policy")
    fibre_channel_interface_policy = module.params.get("fibre_channel_interface_policy")
    slow_drain_policy = module.params.get("slow_drain_policy")
    port_channel_policy = module.params.get("port_channel_policy")
    monitoring_policy = module.params.get("monitoring_policy")
    storm_control_interface_policy = module.params.get("storm_control_interface_policy")
    l2_interface_policy = module.params.get("l2_interface_policy")
    port_security_policy = module.params.get("port_security_policy")
    link_flap_policy = module.params.get("link_flap_policy")
    link_level_flow_control = module.params.get("link_level_flow_control")
    mac_sec_interface_policy = module.params.get("mac_sec_interface_policy")
    copp_policy = module.params.get("copp_policy")
    poe_interface_policy = module.params.get("poe_interface_policy")
    port_authentication = module.params.get("port_authentication")
    dwdm = module.params.get("dwdm")
    aep = module.params.get("aep")
    transceiver_policy = module.params.get("transceiver_policy")
    sync_e_interface_policy = module.params.get("sync_e_interface_policy")

    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)
    if lag_type == "leaf" and port_channel_policy is not None:
        aci.fail_json(
            "port_channel_policy is not a valid parameter for leaf\
 (leaf access port policy group), if used\
 assign null to it (port_channel_policy: null)."
        )
    invalid_parameters = {
        "transceiver_policy": "transceiver_policy is not a valid parameter for link/node (Port Channel, Virtual Port Channel),\
 if used assign null to it (transceiver_policy: null).",
        "port_authentication": "port_authentication is not a valid parameter for link/node (Port Channel, Virtual Port Channel),\
 if used assign null to it (port_authentication: null).",
        "dwdm": "dwdm is not a valid parameter for link/node (Port Channel, Virtual Port Channel),\
 if used assign null to it (dwdm: null).",
        "poe_interface_policy": "poe_interface_policy is not a valid parameter for link/node (Port Channel, Virtual Port Channel),\
 if used assign null to it (poe_interface_policy: null).",
    }

    if lag_type in ["link", "node"]:
        for param, message in invalid_parameters.items():
            if locals().get(param) is not None:
                aci.fail_json(message)

    if lag_type == "leaf":
        aci_class_name = "infraAccPortGrp"
        dn_name = "accportgrp"
        class_config_dict = dict(
            name=policy_group,
            descr=description,
            nameAlias=name_alias,
        )
        # Reset for target_filter
        lag_type = None
    else:
        aci_class_name = "infraAccBndlGrp"
        dn_name = "accbundle"
        class_config_dict = dict(
            name=policy_group,
            descr=description,
            lagT=lag_type,
            nameAlias=name_alias,
        )

    child_configs = [
        dict(
            infraRsCdpIfPol=dict(
                attributes=dict(
                    tnCdpIfPolName=cdp_policy,
                ),
            ),
        ),
        dict(
            infraRsFcIfPol=dict(
                attributes=dict(
                    tnFcIfPolName=fibre_channel_interface_policy,
                ),
            ),
        ),
        dict(
            infraRsHIfPol=dict(
                attributes=dict(
                    tnFabricHIfPolName=link_level_policy,
                ),
            ),
        ),
        dict(
            infraRsL2IfPol=dict(
                attributes=dict(
                    tnL2IfPolName=l2_interface_policy,
                ),
            ),
        ),
        dict(
            infraRsL2PortSecurityPol=dict(
                attributes=dict(
                    tnL2PortSecurityPolName=port_security_policy,
                ),
            ),
        ),
        dict(
            infraRsLacpPol=dict(
                attributes=dict(
                    tnLacpLagPolName=port_channel_policy,
                ),
            ),
        ),
        dict(
            infraRsLldpIfPol=dict(
                attributes=dict(
                    tnLldpIfPolName=lldp_policy,
                ),
            ),
        ),
        dict(
            infraRsMcpIfPol=dict(
                attributes=dict(
                    tnMcpIfPolName=mcp_policy,
                ),
            ),
        ),
        dict(
            infraRsMonIfInfraPol=dict(
                attributes=dict(
                    tnMonInfraPolName=monitoring_policy,
                ),
            ),
        ),
        dict(
            infraRsQosEgressDppIfPol=dict(
                attributes=dict(
                    tnQosDppPolName=egress_data_plane_policing_policy,
                ),
            ),
        ),
        dict(
            infraRsQosIngressDppIfPol=dict(
                attributes=dict(
                    tnQosDppPolName=ingress_data_plane_policing_policy,
                ),
            ),
        ),
        dict(
            infraRsQosPfcIfPol=dict(
                attributes=dict(
                    tnQosPfcIfPolName=priority_flow_control_policy,
                ),
            ),
        ),
        dict(
            infraRsQosSdIfPol=dict(
                attributes=dict(
                    tnQosSdIfPolName=slow_drain_policy,
                ),
            ),
        ),
        dict(
            infraRsStormctrlIfPol=dict(
                attributes=dict(
                    tnStormctrlIfPolName=storm_control_interface_policy,
                ),
            ),
        ),
        dict(
            infraRsStpIfPol=dict(
                attributes=dict(
                    tnStpIfPolName=stp_interface_policy,
                ),
            ),
        ),
    ]

    child_classes = [
        "infraRsAttEntP",
        "infraRsCdpIfPol",
        "infraRsFcIfPol",
        "infraRsHIfPol",
        "infraRsL2IfPol",
        "infraRsL2PortSecurityPol",
        "infraRsLacpPol",
        "infraRsLldpIfPol",
        "infraRsMcpIfPol",
        "infraRsMonIfInfraPol",
        "infraRsQosEgressDppIfPol",
        "infraRsQosIngressDppIfPol",
        "infraRsQosPfcIfPol",
        "infraRsQosSdIfPol",
        "infraRsStormctrlIfPol",
        "infraRsStpIfPol",
    ]

    # Add infraRsattEntP binding only when aep is defined
    if aep is not None:
        child_configs.append(
            dict(
                infraRsAttEntP=dict(
                    attributes=dict(
                        tDn="uni/infra/attentp-{0}".format(aep),
                    ),
                ),
            )
        )

    # Add infraRsSynceEthIfPol/infraRsSynceEthIfPolBndlGrp binding only when sync_e_interface_policy is defined
    if sync_e_interface_policy is not None:
        if lag_type is None:
            child_configs.append(
                dict(
                    infraRsSynceEthIfPol=dict(
                        attributes=dict(
                            tnSynceEthIfPolName=sync_e_interface_policy,
                        ),
                    ),
                )
            )
            child_classes.append("infraRsSynceEthIfPol")
        elif lag_type == "node" or lag_type == "link":
            child_configs.append(
                dict(
                    infraRsSynceEthIfPolBndlGrp=dict(
                        attributes=dict(
                            tnSynceEthIfPolName=sync_e_interface_policy,
                        ),
                    ),
                )
            )
            child_classes.append("infraRsSynceEthIfPolBndlGrp")

    # Add the children only when lag_type == leaf (Leaf Interface specific policies).
    if lag_type is None:
        # Add infraRsOpticsIfPol binding only when transceiver_policy was defined
        if transceiver_policy is not None:
            child_configs.append(
                dict(
                    infraRsOpticsIfPol=dict(
                        attributes=dict(
                            tDn="uni/infra/{0}-{1}".format(transceiver_policy.get("type"), transceiver_policy.get("name")),
                        ),
                    ),
                )
            )
            child_classes.append("infraRsOpticsIfPol")

        if dwdm is not None:
            child_configs.append(
                dict(
                    infraRsDwdmIfPol=dict(
                        attributes=dict(
                            tnDwdmIfPolName=dwdm,
                        ),
                    ),
                )
            )
            child_classes.append("infraRsDwdmIfPol")

        if port_authentication is not None:
            child_configs.append(
                dict(
                    infraRsL2PortAuthPol=dict(
                        attributes=dict(
                            tnL2PortAuthPolName=port_authentication,
                        ),
                    ),
                )
            )
            child_classes.append("infraRsL2PortAuthPol")

        if poe_interface_policy is not None:
            child_configs.append(
                dict(
                    infraRsPoeIfPol=dict(
                        attributes=dict(
                            tnPoeIfPolName=poe_interface_policy,
                        ),
                    ),
                )
            )
            child_classes.append("infraRsPoeIfPol")

    if link_flap_policy is not None:
        child_configs.append(
            dict(
                infraRsLinkFlapPol=dict(
                    attributes=dict(
                        tnFabricLinkFlapPolName=link_flap_policy,
                    ),
                ),
            ),
        )
        child_classes.append("infraRsLinkFlapPol")

    if link_level_flow_control is not None:
        child_configs.append(
            dict(
                infraRsQosLlfcIfPol=dict(
                    attributes=dict(
                        tnQosLlfcIfPolName=link_level_flow_control,
                    ),
                ),
            ),
        )
        child_classes.append("infraRsQosLlfcIfPol")

    if mac_sec_interface_policy is not None:
        child_configs.append(
            dict(
                infraRsMacsecIfPol=dict(
                    attributes=dict(
                        tnMacsecIfPolName=mac_sec_interface_policy,
                    ),
                ),
            ),
        )
        child_classes.append("infraRsMacsecIfPol")

    if copp_policy is not None:
        child_configs.append(
            dict(
                infraRsCoppIfPol=dict(
                    attributes=dict(
                        tnCoppIfPolName=copp_policy,
                    ),
                ),
            ),
        )
        child_classes.append("infraRsCoppIfPol")

    aci.construct_url(
        root_class=dict(
            aci_class=aci_class_name,
            aci_rn="infra/funcprof/{0}-{1}".format(dn_name, policy_group),
            module_object=policy_group,
            target_filter={"name": policy_group, "lagT": lag_type},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=aci_class_name,
            class_config=class_config_dict,
            child_configs=child_configs,
        )

        aci.get_diff(aci_class=aci_class_name)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
