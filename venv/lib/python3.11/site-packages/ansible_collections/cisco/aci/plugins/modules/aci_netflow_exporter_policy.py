#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_netflow_exporter_policy
short_description: Manage Netflow Exporter Policy (netflow:ExporterPol)
description:
- Manage Netflow Exporter Policies for tenants on Cisco ACI fabrics.
- Exporter information for bootstrapping the netflow Collection agent.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  netflow_exporter_policy:
    description:
    - The name of the Netflow Exporter Policy.
    type: str
    aliases: [ netflow_exporter, netflow_exporter_name, name ]
  dscp:
    description:
    - The IP DSCP value.
    - The APIC defaults to C(CS2) when unset during creation.
      It defaults to C(VA) for APIC versions 4.2 or prior.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
  destination_address:
    description:
    - The remote node destination IP address.
    type: str
  destination_port:
    description:
    - The remote node destination port.
    - Accepted values are any valid TCP/UDP port range.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
  source_ip_type:
    description:
    - The type of Exporter source IP Address.
    - It can be one of the available management IP Address for a given leaf or a custom IP Address.
    type: str
    choices: [ custom_source_ip, inband_management_ip, out_of_band_management_ip, ptep ]
  custom_source_address:
    description:
    - The custom source IP address.
    - It can only be used if O(source_ip_type=custom_source_ip).
    type: str
  associated_epg:
   description:
   - The associated EPG.
   - To remove the current associated EPG, pass an empty dictionary.
   type: dict
   aliases: [ epg ]
   suboptions:
      tenant:
        description:
        - The name of the tenant to which the associated AP/EPG  belong.
        type: str
      ap:
        description:
        - The name of the associated Application Profile to which the associated EPG belongs.
        type: str
      epg:
        description:
        - The name of the associated EPG.
        type: str
  associated_extepg:
    description:
    - The associated external EPG.
    - To remove the current associated external EPG, pass an empty dictionary.
    type: dict
    aliases: [ external_epg, associated_external_epg ]
    suboptions:
      tenant:
        description:
        - The name of the tenant to which the associated L3Out/external EPG belong.
        type: str
      l3out:
        description:
        - The name of the L3Out to which the associated external EPG belongs.
        type: str
      extepg:
        description:
        - The name of the associated EPG.
        type: str
  associated_vrf:
    description:
    - The associated VRF.
    - To remove the current associated VRF, pass an empty dictionary.
    type: dict
    aliases: [ vrf, context, associated_context ]
    suboptions:
      tenant:
        description:
        - The name of the tenant to which the associated VRF belongs.
        type: str
      vrf:
        description:
        - The name of the associated VRF.
        type: str
  description:
    description:
    - The description for the Netflow Exporter Policy.
    type: str
    aliases: [ descr ]
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
- The I(tenant) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) can be used for this.
- The I(associated_epg) and I(associated_extepg) are mutually exclusive.
- If the I(associated_epg) is used, the I(epg), the(tenant) and
  the I(ap) must exist before using this module in your play book.
  The M(cisco.aci.aci_epg) and the M(cisco.aci.aci_ap) can be used for this.
- If the I(associated_extepg) is used, the I(extepg), the(tenant) and
  the I(l3out) must exist before using this module in your play book.
  The M(cisco.aci.aci_l3out_extepg) and the M(cisco.aci.aci_l3out) can be used for this.
- If the I(associated_vrf) is used, the I(vrf) and the I(tenant) must exist
  before using this module in your play book.
  The M(cisco.aci.aci_vrf) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_vrf
- module: cisco.aci.aci_ap
- module: cisco.aci.aci_epg
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_l3out_extepg
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(netflow:ExporterPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a new Netflow Exporter Policy
  cisco.aci.aci_netflow_exporter_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    netflow_exporter_policy: my_netflow_exporter_policy
    dscp: CS2
    destination_address: 11.11.11.1
    destination_port: 25
    source_ip_type: custom_source_ip
    custom_source_address: 11.11.11.2
    associated_epg:
      tenant: my_tenant
      ap: my_ap
      epg: my_epg
    associated_vrf:
      tenant: my_tenant
      vrf: my_vrf
    state: present
  delegate_to: localhost

- name: Remove associated EPG and VRF from the new Netflow Exporter Policy
  cisco.aci.aci_netflow_exporter_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    netflow_exporter_policy: my_netflow_exporter_policy
    associated_epg: {}
    associated_vrf: {}
  delegate_to: localhost

- name: Query a Netflow Exporter Policy
  cisco.aci.aci_netflow_exporter_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    netflow_exporter_policy: my_netflow_exporter_policy
    state: query
  delegate_to: localhost

- name: Query all Netflow Exporter Policies in my_tenant
  cisco.aci.aci_netflow_exporter_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    state: query
  delegate_to: localhost

- name: Query all Netflow Exporter Policies
  cisco.aci.aci_netflow_exporter_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Delete a Netflow Exporter Policy
  cisco.aci.aci_netflow_exporter_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    netflow_exporter_policy: my_netflow_exporter_policy
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
    aci_owner_spec,
    aci_contract_dscp_spec,
    associated_netflow_exporter_epg_spec,
    associated_netflow_exporter_extepg_spec,
    associated_netflow_exporter_vrf_spec,
)
from ansible_collections.cisco.aci.plugins.module_utils.constants import MATCH_SOURCE_IP_TYPE_NETFLOW_EXPORTER_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        netflow_exporter_policy=dict(type="str", aliases=["netflow_exporter", "netflow_exporter_name", "name"]),
        dscp=dict((k, aci_contract_dscp_spec()[k]) for k in aci_contract_dscp_spec() if k != "aliases"),
        destination_address=dict(type="str"),
        destination_port=dict(type="str"),
        source_ip_type=dict(type="str", choices=list(MATCH_SOURCE_IP_TYPE_NETFLOW_EXPORTER_MAPPING.keys())),
        custom_source_address=dict(type="str"),
        associated_epg=dict(type="dict", aliases=["epg"], options=associated_netflow_exporter_epg_spec()),
        associated_extepg=dict(type="dict", aliases=["external_epg", "associated_external_epg"], options=associated_netflow_exporter_extepg_spec()),
        associated_vrf=dict(type="dict", aliases=["vrf", "associated_context", "context"], options=associated_netflow_exporter_vrf_spec()),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "netflow_exporter_policy"]],
            ["state", "present", ["tenant", "netflow_exporter_policy", "destination_address", "destination_port"]],
        ],
        mutually_exclusive=[["associated_epg", "associated_extepg"]],
    )

    tenant = module.params.get("tenant")
    description = module.params.get("description")
    netflow_exporter_policy = module.params.get("netflow_exporter_policy")
    dscp = module.params.get("dscp")
    destination_address = module.params.get("destination_address")
    destination_port = module.params.get("destination_port")
    source_ip_type = MATCH_SOURCE_IP_TYPE_NETFLOW_EXPORTER_MAPPING.get(module.params.get("source_ip_type"))
    custom_source_address = module.params.get("custom_source_address")
    associated_epg = module.params.get("associated_epg")
    associated_extepg = module.params.get("associated_extepg")
    associated_vrf = module.params.get("associated_vrf")
    state = module.params.get("state")

    aci = ACIModule(module)

    child_classes = ["netflowRsExporterToCtx", "netflowRsExporterToEPg"]

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="netflowExporterPol",
            aci_rn="exporterpol-{0}".format(netflow_exporter_policy),
            module_object=netflow_exporter_policy,
            target_filter={"name": netflow_exporter_policy},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if associated_vrf is not None:
            if all(value is None for value in associated_vrf.values()) and isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("netflowExporterPol", {}).get("children", {}):
                    if child.get("netflowRsExporterToCtx"):
                        child_configs.extend([dict(netflowRsExporterToCtx=dict(attributes=dict(status="deleted")))])
            elif all(value is not None for value in associated_vrf.values()):
                child_configs.extend(
                    [
                        dict(
                            netflowRsExporterToCtx=dict(
                                attributes=dict(tDn="uni/tn-{0}/ctx-{1}".format(associated_vrf.get("tenant"), associated_vrf.get("vrf")))
                            )
                        ),
                    ]
                )
        if associated_epg is not None:
            if all(value is None for value in associated_epg.values()) and isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("netflowExporterPol", {}).get("children", {}):
                    if child.get("netflowRsExporterToEPg"):
                        child_configs.extend([dict(netflowRsExporterToEPg=dict(attributes=dict(status="deleted")))])
            elif all(value is not None for value in associated_epg.values()):
                child_configs.extend(
                    [
                        dict(
                            netflowRsExporterToEPg=dict(
                                attributes=dict(
                                    tDn="uni/tn-{0}/ap-{1}/epg-{2}".format(associated_epg.get("tenant"), associated_epg.get("ap"), associated_epg.get("epg"))
                                )
                            )
                        ),
                    ]
                )
        elif associated_extepg is not None:
            if all(value is None for value in associated_extepg.values()) and isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("netflowExporterPol", {}).get("children", {}):
                    if child.get("netflowRsExporterToEPg"):
                        child_configs.extend([dict(netflowRsExporterToEPg=dict(attributes=dict(status="deleted")))])
            elif all(value is not None for value in associated_extepg.values()):
                child_configs.extend(
                    [
                        dict(
                            netflowRsExporterToEPg=dict(
                                attributes=dict(
                                    tDn="uni/tn-{0}/out-{1}/instP-{2}".format(
                                        associated_extepg.get("tenant"), associated_extepg.get("l3out"), associated_extepg.get("extepg")
                                    )
                                )
                            )
                        ),
                    ]
                )
        aci.payload(
            aci_class="netflowExporterPol",
            class_config=dict(
                name=netflow_exporter_policy,
                descr=description,
                dscp=dscp,
                dstAddr=destination_address,
                dstPort=destination_port,
                sourceIpType=source_ip_type,
                srcAddr=custom_source_address,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="netflowExporterPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
