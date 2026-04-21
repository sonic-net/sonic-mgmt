#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Tim Cragg (@timcragg)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_fabric_pod_policy_group
short_description: Manage Fabric Pod Policy Groups (fabric:PodPGrp)
description:
- Fabric Pod Policy Group (fabric:PodPGrp) configuration on Cisco ACI fabrics.
options:
  name:
    description:
    - Name of the policy group
    type: str
    aliases: [ policy_group, policy_group_name, pod_policy_group ]
  date_time_policy:
    description:
    - NTP policy to bind to the policy group
    type: str
    aliases: [ ntp_policy ]
  isis_policy:
    description:
    - IS-IS policy to bind to the policy group
    type: str
  coop_group_policy:
    description:
    - COOP group policy to bind to the policy group
    type: str
    aliases: [ coop_policy ]
  bgp_rr_policy:
    description:
    - BGP route reflector policy to bind to the policy group
    type: str
  management_access_policy:
    description:
    - Management access policy to bind to the policy group
    type: str
    aliases: [ management_policy, mgmt_policy ]
  snmp_policy:
    description:
    - SNMP policy to bind to the policy group
    type: str
  macsec_policy:
    description:
    - MACSec policy to bind to the policy group
    type: str
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
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
  description: More information about the internal APIC class B(fabricPodPGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new fabric pod policy group
  cisco.aci.aci_fabric_pod_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_pod_pol_grp
    snmp_policy: my_snmp_pol
    bgp_rr_policy: my_bgp_rr_pol
    state: present
  delegate_to: localhost

- name: Remove a fabric pod policy group
  cisco.aci.aci_fabric_pod_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_pod_pol_grp
    state: absent
  delegate_to: localhost

- name: Query a fabric pod policy group
  cisco.aci.aci_fabric_pod_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_pod_pol_grp
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all fabric pod policy groups
  cisco.aci.aci_fabric_pod_policy_group:
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


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["policy_group", "policy_group_name", "pod_policy_group"]),
        date_time_policy=dict(type="str", aliases=["ntp_policy"]),
        isis_policy=dict(type="str"),
        coop_group_policy=dict(type="str", aliases=["coop_policy"]),
        bgp_rr_policy=dict(type="str"),
        management_access_policy=dict(type="str", aliases=["management_policy", "mgmt_policy"]),
        snmp_policy=dict(type="str"),
        macsec_policy=dict(type="str"),
        name_alias=dict(type="str"),
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
    aci = ACIModule(module)

    name = module.params.get("name")
    date_time_policy = module.params.get("date_time_policy")
    isis_policy = module.params.get("isis_policy")
    coop_group_policy = module.params.get("coop_group_policy")
    bgp_rr_policy = module.params.get("bgp_rr_policy")
    management_access_policy = module.params.get("management_access_policy")
    snmp_policy = module.params.get("snmp_policy")
    macsec_policy = module.params.get("macsec_policy")
    name_alias = module.params.get("name_alias")
    state = module.params.get("state")
    child_classes = [
        "fabricRsSnmpPol",
        "fabricRsPodPGrpIsisDomP",
        "fabricRsPodPGrpCoopP",
        "fabricRsPodPGrpBGPRRP",
        "fabricRsTimePol",
        "fabricRsMacsecPol",
        "fabricRsCommPol",
    ]

    aci.construct_url(
        root_class=dict(
            aci_class="fabricPodPGrp",
            aci_rn="fabric/funcprof/podpgrp-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if date_time_policy is not None:
            child_configs.append(dict(fabricRsTimePol=dict(attributes=dict(tnDatetimePolName=date_time_policy))))
        if isis_policy is not None:
            child_configs.append(dict(fabricRsPodPGrpIsisDomP=dict(attributes=dict(tnIsisDomPolName=isis_policy))))
        if coop_group_policy is not None:
            child_configs.append(dict(fabricRsPodPGrpCoopP=dict(attributes=dict(tnCoopPolName=coop_group_policy))))
        if bgp_rr_policy is not None:
            child_configs.append(dict(fabricRsPodPGrpBGPRRP=dict(attributes=dict(tnBgpInstPolName=bgp_rr_policy))))
        if management_access_policy is not None:
            child_configs.append(dict(fabricRsCommPol=dict(attributes=dict(tnCommPolName=management_access_policy))))
        if snmp_policy is not None:
            child_configs.append(dict(fabricRsSnmpPol=dict(attributes=dict(tnSnmpPolName=snmp_policy))))
        if macsec_policy is not None:
            child_configs.append(dict(fabricRsMacsecPol=dict(attributes=dict(tnMacsecFabIfPolName=macsec_policy))))
        aci.payload(
            aci_class="fabricPodPGrp",
            class_config=dict(name=name, nameAlias=name_alias),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="fabricPodPGrp")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
