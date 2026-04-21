#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Manuel Widmer <mawidmer@cisco.com>
# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_vmm_vswitch_policy
short_description: Manage vSwitch policy for VMware virtual domains profiles (vmm:VSwitchPolicyCont)
description:
- Manage vSwitch policy for VMware VMM domains on Cisco ACI fabrics.
options:
  port_channel_policy:
    description:
    - Name of the fabric access port-channel policy.
    type: str
  lldp_policy:
    description:
    - Name of the fabric access LLDP policy.
    type: str
  cdp_policy:
    description:
    - Name of the fabric access CDP policy.
    type: str
  mtu_policy:
    description:
    - VMWare only.
    - Name of the fabric access MTU policy.
    type: str
  domain:
    description:
    - Name of the virtual domain profile.
    type: str
    aliases: [ domain_name, domain_profile ]
  enhanced_lag:
    description:
    - List of enhanced LAG policies if vSwitch needs to be connected via VPC.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - Name of the enhanced Lag policy.
        type: str
        required: true
      lacp_mode:
        description:
        - LACP port channel mode.
        type: str
        choices: [ active, passive ]
      load_balancing_mode:
        description:
        - Load balancing mode of the port channel.
        - See also https://pubhub.devnetcloud.com/media/apic-mim-ref-421/docs/MO-lacpEnhancedLagPol.html.
        type: str
        choices:
          - dst-ip
          - dst-ip-l4port
          - dst-ip-vlan
          - dst-ip-l4port-vlan
          - dst-mac
          - dst-l4port
          - src-ip
          - src-ip-l4port
          - src-ip-vlan
          - src-ip-l4port-vlan
          - src-mac
          - src-l4port
          - src-dst-ip
          - src-dst-ip-l4port
          - src-dst-ip-vlan
          - src-dst-ip-l4port-vlan
          - src-dst-mac
          - src-dst-l4port
          - src-port-id
          - vlan
      number_uplinks:
        description:
        - Number of uplinks, must be between 2 and 8.
        type: int
  stp_policy:
    description:
    - SCVMM only.
    - Name of the STP policy.
    type: str
  netflow_exporter:
    description:
    - Parameters for the netflow exporter policy
    type: dict
    suboptions:
      name:
        description:
        - Name of the netflow exporter policy
        type: str
        required: true
      active_flow_timeout:
        description:
        - Specifies the delay in seconds that NetFlow waits after the active flow is initiated, after which NetFlow sends the collected data.
        - The range is from 60 to 3600. The default value is 60
        type: int
      idle_flow_timeout:
        description:
        - Specifies the delay in seconds that NetFlow waits after the idle flow is initiated, after which NetFlow sends the collected data.
        - The range is from 10 to 600. The default value is 15.
        type: int
      sampling_rate:
        description:
        - (VDS only) Specifies how many packets that NetFlow will drop after every collected packet.
          If you specify a value of 0, then NetFlow does not drop any packets.
        - The range is from 0 to 1000. The default value is 0.
        type: int
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  vm_provider:
    description:
    - The VM platform for VMM Domains.
    - Support for Kubernetes was added in ACI v3.0.
    - Support for CloudFoundry, OpenShift and Red Hat was added in ACI v3.1.
    type: str
    choices: [ cloudfoundry, kubernetes, microsoft, openshift, openstack, redhat, vmware ]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- module: cisco.aci.aci_domain
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(vmm:VSwitchPolicyCont).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Manuel Widmer (@lumean)
- Anvitha Jain (@anvitha-jain)
"""

EXAMPLES = r"""
- name: Add a vSwitch policy with LLDP
  cisco.aci.aci_vmm_vswitch_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    lldp_policy: LLDP_ENABLED
    domain: vmware_dom
    vm_provider: vmware
    state: present

- name: Add a vSwitch policy with link aggregation
  cisco.aci.aci_vmm_vswitch_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    port_channel_policy: LACP_ACTIVE
    lldp_policy: LLDP_ENABLED
    domain: vmware_dom
    vm_provider: vmware
    enhanced_lag:
      - name: my_lacp_uplink
        lacp_mode: active
        load_balancing_mode: src-dst-ip
        number_uplinks: 2
    state: present

- name: Remove vSwitch Policy from VMware VMM domain
  cisco.aci.aci_vmm_vswitch_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: vmware_dom
    vm_provider: vmware
    state: absent

- name: Query the vSwitch policy of the VMWare domain
  cisco.aci.aci_vmm_vswitch_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: vmware_dom
    vm_provider: vmware
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    enhanced_lag_spec,
    netflow_spec,
    aci_annotation_spec,
    aci_owner_spec,
)
from ansible_collections.cisco.aci.plugins.module_utils.constants import (
    VM_PROVIDER_MAPPING,
)

# via UI vSwitch Policy can only be added for VMware and Microsoft vmm domains
# behavior for other domains is currently untested.

# enhanced_lag_spec = dict(
#     name=dict(type='str', required=True),
#     lacp_mode=dict(type='str', choices=['active', 'passive']),
#     load_balancing_mode=dict(
#         type='str',
#         choices=['dst-ip', 'dst-ip-l4port', 'dst-ip-vlan', 'dst-ip-l4port-vlan', 'dst-mac', 'dst-l4port',
#                  'src-ip', 'src-ip-l4port', 'src-ip-vlan', 'src-ip-l4port-vlan', 'src-mac', 'src-l4port',
#                  'src-dst-ip', 'src-dst-ip-l4port', 'src-dst-ip-vlan', 'src-dst-ip-l4port-vlan', 'src-dst-mac',
#                  'src-dst-l4port', 'src-port-id', 'vlan']),
#     number_uplinks=dict(type='int'),
# )
# netflow_spec = dict(
#     name=dict(type='str', required=True),
#     active_flow_timeout=dict(type='int'),
#     idle_flow_timeout=dict(type='int'),
#     sampling_rate=dict(type='int'),
# )


def main():

    # Remove nutanix from VM_PROVIDER_MAPPING as it is not supported
    CLEAN_VM_PROVIDER_MAPPING = VM_PROVIDER_MAPPING.copy()
    CLEAN_VM_PROVIDER_MAPPING.pop("nutanix")

    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        port_channel_policy=dict(type="str"),
        lldp_policy=dict(type="str"),
        cdp_policy=dict(type="str"),
        mtu_policy=dict(type="str"),
        stp_policy=dict(type="str"),
        enhanced_lag=dict(type="list", elements="dict", options=enhanced_lag_spec()),
        netflow_exporter=dict(type="dict", options=netflow_spec()),
        domain=dict(type="str", aliases=["domain_name", "domain_profile"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        vm_provider=dict(type="str", choices=list(CLEAN_VM_PROVIDER_MAPPING)),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["domain", "vm_provider"]],
            ["state", "present", ["domain", "vm_provider"]],
        ],
    )

    port_channel_policy = module.params.get("port_channel_policy")
    lldp_policy = module.params.get("lldp_policy")
    cdp_policy = module.params.get("cdp_policy")
    mtu_policy = module.params.get("mtu_policy")
    stp_policy = module.params.get("stp_policy")
    netflow_exporter = module.params.get("netflow_exporter")
    enhanced_lag = module.params.get("enhanced_lag")
    domain = module.params.get("domain")
    state = module.params.get("state")
    vm_provider = module.params.get("vm_provider")

    aci = ACIModule(module)
    vswitch_class = "vmmVSwitchPolicyCont"

    child_classes = ["vmmRsVswitchOverrideLldpIfPol", "vmmRsVswitchOverrideLacpPol", "vmmRsVswitchOverrideCdpIfPol", "lacpEnhancedLagPol"]
    if mtu_policy is not None:
        child_classes.append("vmmRsVswitchOverrideMtuPol")

    if stp_policy is not None:
        child_classes.append("vmmRsVswitchOverrideStpPol")

    if isinstance(netflow_exporter, dict):
        child_classes.append("vmmRsVswitchExporterPol")

    aci.construct_url(
        root_class=dict(
            aci_class="vmmProvP",
            aci_rn="vmmp-{0}".format(CLEAN_VM_PROVIDER_MAPPING.get(vm_provider)),
            module_object=vm_provider,
            target_filter={"name": vm_provider},
        ),
        subclass_1=dict(
            aci_class="vmmDomP",
            aci_rn="dom-{0}".format(domain),
            module_object=domain,
            target_filter={"name": domain},
        ),
        subclass_2=dict(
            aci_class="vmmVSwitchPolicyCont",
            aci_rn="vswitchpolcont",
            module_object="vswitchpolcont",
            target_filter={"name": "vswitchpolcont"},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        children = list()

        if port_channel_policy is not None:
            children.append(dict(vmmRsVswitchOverrideLacpPol=dict(attributes=dict(tDn="uni/infra/lacplagp-{0}".format(port_channel_policy)))))

        if lldp_policy is not None:
            children.append(dict(vmmRsVswitchOverrideLldpIfPol=dict(attributes=dict(tDn="uni/infra/lldpIfP-{0}".format(lldp_policy)))))

        if cdp_policy is not None:
            children.append(dict(vmmRsVswitchOverrideCdpIfPol=dict(attributes=dict(tDn="uni/infra/cdpIfP-{0}".format(cdp_policy)))))

        if mtu_policy is not None:
            children.append(dict(vmmRsVswitchOverrideMtuPol=dict(attributes=dict(tDn="uni/fabric/l2pol-{0}".format(mtu_policy)))))

        if stp_policy is not None:
            children.append(dict(vmmRsVswitchOverrideStpPol=dict(attributes=dict(tDn="uni/infra/ifPol-{0}".format(stp_policy)))))

        if isinstance(netflow_exporter, dict):
            children.append(
                dict(
                    vmmRsVswitchExporterPol=dict(
                        attributes=dict(
                            tDn="uni/infra/vmmexporterpol-{0}".format(netflow_exporter["name"]),
                            activeFlowTimeOut=netflow_exporter["active_flow_timeout"],
                            idleFlowTimeOut=netflow_exporter["idle_flow_timeout"],
                            samplingRate=netflow_exporter["sampling_rate"],
                        )
                    )
                )
            )

        if isinstance(enhanced_lag, list):
            for lag_dict in enhanced_lag:
                children.append(
                    dict(
                        lacpEnhancedLagPol=dict(
                            attributes=dict(
                                name=lag_dict["name"],
                                mode=lag_dict["lacp_mode"],
                                lbmode=lag_dict["load_balancing_mode"],
                                numLinks=lag_dict["number_uplinks"],
                            )
                        )
                    )
                )

        aci.payload(aci_class=vswitch_class, class_config=dict(rn="vswitchpolcont"), child_configs=children)

        aci.get_diff(aci_class=vswitch_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
