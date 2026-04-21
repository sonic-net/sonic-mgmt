#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Jacob McGill <jmcgill298>
# Copyright: (c) 2020, Shreyas Srish <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_epg_to_domain
short_description: Bind EPGs to Domains (fv:RsDomAtt)
description:
- Bind EPGs to Physical and Virtual Domains on Cisco ACI fabrics.
options:
  allow_useg:
    description:
    - Allows micro-segmentation.
    - The APIC defaults to C(encap) when unset during creation.
    type: str
    choices: [ encap, useg ]
  ap:
    description:
    - Name of an existing application network profile, that will contain the EPGs.
    type: str
    aliases: [ app_profile, app_profile_name ]
  deploy_immediacy:
    description:
    - Determines when the policy is pushed to hardware Policy CAM.
    - The APIC defaults to C(lazy) when unset during creation.
    type: str
    choices: [ immediate, lazy ]
  domain:
    description:
    - Name of the physical or virtual domain being associated with the EPG.
    type: str
    aliases: [ domain_name, domain_profile ]
  domain_type:
    description:
    - Specify whether the Domain is a physical (phys), a virtual (vmm) or an L2 external domain association (l2dom).
    type: str
    choices: [ l2dom, phys, vmm ]
    aliases: [ type ]
  encap:
    description:
    - The VLAN encapsulation for the EPG when binding a VMM Domain in static VLAN mode.
    - The VLAN mode in UI is set to static when O(encap) is not set.
    - This acts as the secondary encap when using useg.
    - Accepted values range between C(1) and C(4096).
    type: int
  encap_mode:
    description:
    - The encapsulation method to be used.
    - The APIC defaults to C(auto) when unset during creation.
    - If vxlan is selected, switching_mode must be "AVE".
    type: str
    choices: [ auto, vlan, vxlan ]
  switching_mode:
    description:
    - Switching Mode used by the switch
    type: str
    choices: [ AVE, native ]
    default: native
  epg:
    description:
    - Name of the end point group.
    type: str
    aliases: [ epg_name, name ]
  enhanced_lag_policy:
    description:
    - Name of the VMM Domain Enhanced Lag Policy.
    type: str
    aliases: [ lag_policy ]
  vmm_uplink_active:
    description:
    - A list of active uplink IDs.
    - The order decides the order in which active uplinks take over for a failed uplink.
    - At least one active uplink must remain specified in the list when an active uplink was previously configured.
    type: list
    elements: str
  vmm_uplink_standby:
    description:
    - A list of standby uplink IDs.
    - At least one standby uplink must remain specified in the list when no active uplink is configured.
    type: list
    elements: str
  netflow:
    description:
    - Determines if netflow should be enabled.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  primary_encap:
    description:
    - Determines the primary VLAN ID when using useg.
    - Accepted values range between C(1) and C(4096).
    type: int
  resolution_immediacy:
    description:
    - Determines when the policies should be resolved and available.
    - The APIC defaults to C(lazy) when unset during creation.
    type: str
    choices: [ immediate, lazy, pre-provision ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  promiscuous:
    description:
    - Allow/Disallow promiscuous mode in vmm domain
    type: str
    choices: [ accept, reject ]
    default: reject
  vm_provider:
    description:
    - The VM platform for VMM Domains.
    - Support for Kubernetes was added in ACI v3.0.
    - Support for CloudFoundry, OpenShift and Red Hat was added in ACI v3.1.
    type: str
    choices: [ cloudfoundry, kubernetes, microsoft, openshift, openstack, redhat, vmware, nutanix ]
  custom_epg_name:
    description:
    - The custom epg name in VMM domain association.
    type: str
  delimiter:
    description:
    - The delimiter.
    type: str
    choices: [ "|", "~", "!", "@", "^", "+", "=", "_" ]
  untagged_vlan:
    description:
    - The access vlan is untagged.
    type: bool
  port_binding:
    description:
    - The port binding method.
    type: str
    choices: [ dynamic, ephemeral, static ]
  port_allocation:
    description:
    - The port allocation method.
    type: str
    choices: [ elastic, fixed ]
  number_of_ports:
    description:
    - The number of ports.
    type: int
  forged_transmits:
    description:
    - Allow forged transmits. A forged transmit occurs when a network adapter starts sending out traffic that identifies itself as something else.
    type: str
    choices: [ accept, reject ]
    default: reject
  mac_changes:
    description:
    - Allows definition of new MAC addresses for the network adapter within the virtual machine (VM).
    type: str
    choices: [ accept, reject ]
    default: reject
  epg_cos:
    description:
    - The class of service (CoS).
    - The APIC defaults to C(cos_0) when unset during creation.
    type: str
    choices: [ cos_0, cos_1, cos_2, cos_3, cos_4, cos_5, cos_6, cos_7 ]
  epg_cos_preference:
    description:
    - The CoS preference.
    - The APIC defaults to C(disabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
  ipam_dhcp_override:
    description:
    - The IP Address Management (IPAM) Dynamic Host Configuration Protocol (DHCP) override.
    - Only applicable for Nutanix domains.
    type: str
  ipam_enabled:
    description:
    - The IPAM enabled state.
    - Only applicable for Nutanix domains.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  ipam_gateway:
    description:
    - The IPAM gateway.
    - Only applicable for Nutanix domains.
    type: str
  lag_policy_name:
    description:
    - The link aggregation group (LAG) policy name.
    type: str
  netflow_direction:
    description:
    - The NetFlow monitoring direction.
    - The APIC defaults to C(both) when unset during creation.
    type: str
    choices: [ both, ingress, egress ]
  primary_encap_inner:
    description:
    - The primary inner encapsulation.
    - This is used for the portgroup at the VMWare Distributed Virtual Switch (DVS).
    - This VLAN is internal to the DVS and is used for communication between the other VMs and the AVE VM at a host.
    - Traffic is not forwarded to the fabric over the VLAN.
    - Only applicable for Cisco ACI Virtual Edge (AVE) domains.
    - Accepted values range between C(1) and C(4096).
    type: int
  secondary_encap_inner:
    description:
    - The secondary inner encapsulation.
    - This is used for the portgroup at the VMWare DVS.
    - This VLAN is internal to the DVS and is used for communication between the other VMs and the AVE VM at a host.
    - Traffic is not forwarded to the fabric over the VLAN.
    - Only applicable for AVE domains.
    - Accepted values range between C(1) and C(4096).
    type: int
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(tenant), C(ap), C(epg), and C(domain) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) M(cisco.aci.aci_ap), M(cisco.aci.aci_epg) M(cisco.aci.aci_domain) modules can be used for this.
- OpenStack VMM domains must not be created using this module. The OpenStack VMM domain is created directly
  by the Cisco APIC Neutron plugin as part of the installation and configuration.
  This module can be used to query status of an OpenStack VMM domain.
seealso:
- module: cisco.aci.aci_ap
- module: cisco.aci.aci_epg
- module: cisco.aci.aci_domain
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:RsDomAtt).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Jacob McGill (@jmcgill298)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new physical domain to EPG binding
  cisco.aci.aci_epg_to_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    domain: anstest
    domain_type: phys
    state: present
  delegate_to: localhost

- name: Remove an existing physical domain to EPG binding
  cisco.aci.aci_epg_to_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    domain: anstest
    domain_type: phys
    state: absent
  delegate_to: localhost

- name: Query a specific physical domain to EPG binding
  cisco.aci.aci_epg_to_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    domain: anstest
    domain_type: phys
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all domain to EPG bindings
  cisco.aci.aci_epg_to_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible_collections.cisco.aci.plugins.module_utils.constants import COS_MAPPING, VM_PROVIDER_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        allow_useg=dict(type="str", choices=["encap", "useg"]),
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),  # Not required for querying all objects
        deploy_immediacy=dict(type="str", choices=["immediate", "lazy"]),
        domain=dict(type="str", aliases=["domain_name", "domain_profile"]),  # Not required for querying all objects
        domain_type=dict(type="str", choices=["l2dom", "phys", "vmm"], aliases=["type"]),  # Not required for querying all objects
        encap=dict(type="int"),
        encap_mode=dict(type="str", choices=["auto", "vlan", "vxlan"]),
        switching_mode=dict(type="str", default="native", choices=["AVE", "native"]),
        epg=dict(type="str", aliases=["name", "epg_name"]),  # Not required for querying all objects
        enhanced_lag_policy=dict(type="str", aliases=["lag_policy"]),
        vmm_uplink_active=dict(type="list", elements="str"),
        vmm_uplink_standby=dict(type="list", elements="str"),
        netflow=dict(type="bool"),
        primary_encap=dict(type="int"),
        resolution_immediacy=dict(type="str", choices=["immediate", "lazy", "pre-provision"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        vm_provider=dict(type="str", choices=list(VM_PROVIDER_MAPPING)),
        promiscuous=dict(type="str", default="reject", choices=["accept", "reject"]),
        custom_epg_name=dict(type="str"),
        delimiter=dict(type="str", choices=["|", "~", "!", "@", "^", "+", "=", "_"]),
        untagged_vlan=dict(type="bool"),
        port_binding=dict(type="str", choices=["dynamic", "ephemeral", "static"]),
        port_allocation=dict(type="str", choices=["elastic", "fixed"]),
        number_of_ports=dict(type="int"),
        forged_transmits=dict(type="str", default="reject", choices=["accept", "reject"]),
        mac_changes=dict(type="str", default="reject", choices=["accept", "reject"]),
        epg_cos=dict(type="str", choices=list(COS_MAPPING)),
        epg_cos_preference=dict(type="str", choices=["enabled", "disabled"]),
        ipam_dhcp_override=dict(type="str"),
        ipam_enabled=dict(type="bool"),
        ipam_gateway=dict(type="str"),
        lag_policy_name=dict(type="str"),
        netflow_direction=dict(type="str", choices=["both", "ingress", "egress"]),
        primary_encap_inner=dict(type="int"),
        secondary_encap_inner=dict(type="int"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["domain_type", "vmm", ["vm_provider"]],
            ["state", "absent", ["ap", "domain", "domain_type", "epg", "tenant"]],
            ["state", "present", ["ap", "domain", "domain_type", "epg", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    allow_useg = module.params.get("allow_useg")
    ap = module.params.get("ap")
    deploy_immediacy = module.params.get("deploy_immediacy")
    domain = module.params.get("domain")
    domain_type = module.params.get("domain_type")
    vm_provider = module.params.get("vm_provider")
    promiscuous = module.params.get("promiscuous")
    custom_epg_name = module.params.get("custom_epg_name")
    encap = format_vlan(aci, module.params.get("encap"))
    encap_mode = module.params.get("encap_mode")
    switching_mode = module.params.get("switching_mode")
    epg = module.params.get("epg")
    enhanced_lag_policy = module.params.get("enhanced_lag_policy")
    vmm_uplink_active = module.params.get("vmm_uplink_active")
    vmm_uplink_standby = module.params.get("vmm_uplink_standby")
    netflow = aci.boolean(module.params.get("netflow"), "enabled", "disabled")
    primary_encap = format_vlan(aci, module.params.get("primary_encap"))
    resolution_immediacy = module.params.get("resolution_immediacy")
    state = module.params.get("state")
    tenant = module.params.get("tenant")

    if domain_type in ["l2dom", "phys"] and vm_provider is not None:
        module.fail_json(msg="Domain type '%s' cannot have a 'vm_provider'" % domain_type)

    delimiter = module.params.get("delimiter")
    untagged_vlan = "yes" if module.params.get("untagged_vlan") is True else "no"
    port_binding = module.params.get("port_binding")
    if port_binding == "static" or port_binding == "dynamic":
        port_binding = "{0}Binding".format(port_binding)
    port_allocation = module.params.get("port_allocation")
    number_of_ports = module.params.get("number_of_ports")
    forged_transmits = module.params.get("forged_transmits")
    mac_changes = module.params.get("mac_changes")
    epg_cos = COS_MAPPING.get(module.params.get("epg_cos"))
    epg_cos_pref = module.params.get("epg_cos_preference")
    ipam_dhcp_override = module.params.get("ipam_dhcp_override")
    ipam_enabled = aci.boolean(module.params.get("ipam_enabled"))
    ipam_gateway = module.params.get("ipam_gateway")
    lag_policy_name = module.params.get("lag_policy_name")
    netflow_direction = module.params.get("netflow_direction")
    primary_encap_inner = format_vlan(aci, module.params.get("primary_encap_inner"))
    secondary_encap_inner = format_vlan(aci, module.params.get("secondary_encap_inner"))

    child_classes = None
    child_configs = None

    # Compile the full domain for URL building
    if domain_type == "vmm":
        epg_domain = "uni/vmmp-{0}/dom-{1}".format(VM_PROVIDER_MAPPING[vm_provider], domain)
        child_configs = [dict(vmmSecP=dict(attributes=dict(allowPromiscuous=promiscuous, forgedTransmits=forged_transmits, macChanges=mac_changes)))]
        # check with child classes added on all versions
        child_classes = ["vmmSecP"]

        if vmm_uplink_active is not None or vmm_uplink_standby is not None:
            uplink_order_cont = dict(fvUplinkOrderCont=dict(attributes=dict()))
            if vmm_uplink_active is not None:
                uplink_order_cont["fvUplinkOrderCont"]["attributes"]["active"] = ",".join(vmm_uplink_active)
            if vmm_uplink_standby is not None:
                uplink_order_cont["fvUplinkOrderCont"]["attributes"]["standby"] = ",".join(vmm_uplink_standby)
            child_configs.append(uplink_order_cont)
            child_classes.append("fvUplinkOrderCont")

        if enhanced_lag_policy is not None:
            lag_policy = epg_domain + "/vswitchpolcont/enlacplagp-{0}".format(enhanced_lag_policy)
            child_configs.append(
                dict(
                    fvAEPgLagPolAtt=dict(
                        attributes=dict(annotation=""), children=[dict(fvRsVmmVSwitchEnhancedLagPol=dict(attributes=dict(annotation="", tDn=lag_policy)))]
                    )
                )
            )
            child_classes.append("fvAEPgLagPolAtt")

    elif domain_type == "l2dom":
        epg_domain = "uni/l2dom-{0}".format(domain)
    elif domain_type == "phys":
        epg_domain = "uni/phys-{0}".format(domain)
    else:
        epg_domain = None

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvAp",
            aci_rn="ap-{0}".format(ap),
            module_object=ap,
            target_filter={"name": ap},
        ),
        subclass_2=dict(
            aci_class="fvAEPg",
            aci_rn="epg-{0}".format(epg),
            module_object=epg,
            target_filter={"name": epg},
        ),
        subclass_3=dict(
            aci_class="fvRsDomAtt",
            aci_rn="rsdomAtt-[{0}]".format(epg_domain),
            module_object=epg_domain,
            target_filter={"tDn": epg_domain},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fvRsDomAtt",
            class_config=dict(
                classPref=allow_useg,
                encap=encap,
                encapMode=encap_mode,
                switchingMode=switching_mode,
                instrImedcy=deploy_immediacy,
                netflowPref=netflow,
                primaryEncap=primary_encap,
                resImedcy=resolution_immediacy,
                customEpgName=custom_epg_name,
                delimiter=delimiter,
                untagged=untagged_vlan,
                bindingType=port_binding,
                portAllocation=port_allocation,
                numPorts=number_of_ports,
                epgCos=epg_cos,
                epgCosPref=epg_cos_pref,
                ipamDhcpOverride=ipam_dhcp_override,
                ipamEnabled=ipam_enabled,
                ipamGateway=ipam_gateway,
                lagPolicyName=lag_policy_name,
                netflowDir=netflow_direction,
                primaryEncapInner=primary_encap_inner,
                secondaryEncapInner=secondary_encap_inner,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="fvRsDomAtt")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


def format_vlan(aci, vlan):
    if vlan in range(1, 4097):
        return "vlan-{0}".format(vlan)
    if vlan is not None:
        aci.fail_json(msg="Valid VLAN assignments are from 1 to 4096")
    return vlan


if __name__ == "__main__":
    main()
