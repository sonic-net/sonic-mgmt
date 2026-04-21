#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Tim Cragg (@timcragg)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_fabric_switch_policy_group
short_description: Manage Fabric Switch Policy Group objects (fabric:LeNodePGrp and fabric:SpNodePGrp)
description:
- Manage Fabric Switch Policy Group configuration on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the Fabric Switch Policy Group.
    type: str
    aliases: [ 'policy_group', 'policy_group_name' ]
  description:
    description:
    - Description for the Fabric Switch Policy Group.
    type: str
  switch_type:
    description:
    - Whether this is a leaf or spine Fabric Switch Policy Group.
    type: str
    choices: [ leaf, spine ]
    required: true
  monitoring_policy:
    description:
    - Monitoring Policy to attach to this Fabric Switch Policy Group.
    type: str
    aliases: [ 'monitoring', 'fabricRsMonInstFabricPol' ]
  tech_support_export_policy:
    description:
    - Tech Support Export Policy to attach to this Fabric Switch Policy Group.
    type: str
    aliases: [ 'tech_support', 'tech_support_export', 'fabricRsNodeTechSupP']
  core_export_policy:
    description:
    - Core Export Policy to attach to this Fabric Switch Policy Group.
    type: str
    aliases: [ 'core', 'core_export', 'fabricRsNodeCoreP' ]
  inventory_policy:
    description:
    - Inventory Policy to attach to this Fabric Switch Policy Group.
    type: str
    aliases: [ 'inventory', 'fabricRsCallhomeInvPol' ]
  power_redundancy_policy:
    description:
    - Power Redundancy Policy to atttach to this Fabric Switch Policy Group.
    type: str
    aliases: [ 'power_redundancy', 'fabricRsPsuInstPol' ]
  twamp_server_policy:
    description:
    - TWAMP Server Policy to attach to this Fabric Switch Policy Group.
    type: str
    aliases: [ 'twamp_server', 'fabricRsTwampServerPol' ]
  twamp_responder_policy:
    description:
    - TWAMP Responder Policy to attach to this Fabric Switch Policy Group.
    type: str
    aliases: [ 'twamp_responder', 'fabricRsTwampResponderPol' ]
  node_control_policy:
    description:
    - Node Control Policy to attach to this Fabric Switch Policy Group.
    type: str
    aliases: [ 'node_control', 'fabricRsNodeCtrl' ]
  analytics_cluster:
    description:
    - Name of the analytics cluster. Requires analytics_name to be present.
    type: str
  analytics_name:
    description:
    - Name of the analytics policy. Requires analytics_cluster to be present.
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(fabric:LeNodePGrp) and B(fabric:SpNodePGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new Fabric Leaf Policy Group
  cisco.aci.aci_fabric_switch_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_fabric_leaf_policy_group
    switch_type: leaf
    monitoring_policy: my_monitor_policy
    inventory_policy: my_inv_policy
    state: present
    delegate_to: localhost

- name: Remove existing analytics and monitoring policy bindings from a Policy Group
  cisco.aci.aci_fabric_switch_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_fabric_leaf_policy_group
    switch_type: leaf
    monitoring_policy: ""
    analytics_cluster: ""
    analytics_name: ""
    state: present
    delegate_to: localhost

- name: Remove a Fabric Leaf Policy Group
  cisco.aci.aci_fabric_switch_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_fabric_leaf_policy_group
    switch_type: leaf
    state: absent
    delegate_to: localhost

- name: Query a Fabric Leaf Policy Group
  cisco.aci.aci_fabric_switch_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_fabric_leaf_policy_group
    switch_type: leaf
    state: query
    delegate_to: localhost
    register: query_result

- name: Query all Fabric Leaf Policy Groups
  cisco.aci.aci_fabric_switch_policy_group:
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec

ACI_CLASS_MAPPING = dict(
    spine={
        "class": "fabricSpNodePGrp",
        "rn": "spnodepgrp-",
    },
    leaf={
        "class": "fabricLeNodePGrp",
        "rn": "lenodepgrp-",
    },
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["policy_group", "policy_group_name"]),
        switch_type=dict(type="str", choices=["leaf", "spine"], required=True),
        monitoring_policy=dict(type="str", aliases=["monitoring", "fabricRsMonInstFabricPol"]),
        tech_support_export_policy=dict(type="str", aliases=["tech_support", "tech_support_export", "fabricRsNodeTechSupP"]),
        core_export_policy=dict(type="str", aliases=["core", "core_export", "fabricRsNodeCoreP"]),
        inventory_policy=dict(type="str", aliases=["inventory", "fabricRsCallhomeInvPol"]),
        power_redundancy_policy=dict(type="str", aliases=["power_redundancy", "fabricRsPsuInstPol"]),
        twamp_server_policy=dict(type="str", aliases=["twamp_server", "fabricRsTwampServerPol"]),
        twamp_responder_policy=dict(type="str", aliases=["twamp_responder", "fabricRsTwampResponderPol"]),
        node_control_policy=dict(type="str", aliases=["node_control", "fabricRsNodeCtrl"]),
        analytics_cluster=dict(type="str"),
        analytics_name=dict(type="str"),
        description=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
        required_together=[
            ("analytics_cluster", "analytics_name"),
        ],
    )

    name = module.params.get("name")
    switch_type = module.params.get("switch_type")
    description = module.params.get("description")
    monitoring_policy = module.params.get("monitoring_policy")
    tech_support_export_policy = module.params.get("tech_support_export_policy")
    core_export_policy = module.params.get("core_export_policy")
    inventory_policy = module.params.get("inventory_policy")
    power_redundancy_policy = module.params.get("power_redundancy_policy")
    twamp_server_policy = module.params.get("twamp_server_policy")
    twamp_responder_policy = module.params.get("twamp_responder_policy")
    node_control_policy = module.params.get("node_control_policy")
    analytics_cluster = module.params.get("analytics_cluster")
    analytics_name = module.params.get("analytics_name")
    state = module.params.get("state")
    child_classes = [
        "fabricRsMonInstFabricPol",
        "fabricRsNodeTechSupP",
        "fabricRsNodeCoreP",
        "fabricRsCallhomeInvPol",
        "fabricRsPsuInstPol",
        "fabricRsTwampServerPol",
        "fabricRsTwampResponderPol",
        "fabricRsNodeCtrl",
        "fabricRsNodeCfgSrv",
    ]

    aci_class = ACI_CLASS_MAPPING[switch_type]["class"]
    aci_rn = ACI_CLASS_MAPPING[switch_type]["rn"]

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class=aci_class,
            aci_rn="fabric/funcprof/{0}{1}".format(aci_rn, name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []

        if monitoring_policy is not None:
            child_configs.append(dict(fabricRsMonInstFabricPol=dict(attributes=dict(tnMonFabricPolName=monitoring_policy))))
        if tech_support_export_policy is not None:
            child_configs.append(dict(fabricRsNodeTechSupP=dict(attributes=dict(tnDbgexpTechSupPName=tech_support_export_policy))))
        if core_export_policy is not None:
            child_configs.append(dict(fabricRsNodeCoreP=dict(attributes=dict(tnDbgexpCorePName=core_export_policy))))
        if inventory_policy is not None:
            child_configs.append(dict(fabricRsCallhomeInvPol=dict(attributes=dict(tnCallhomeInvPName=inventory_policy))))
        if power_redundancy_policy is not None:
            child_configs.append(dict(fabricRsPsuInstPol=dict(attributes=dict(tnPsuInstPolName=power_redundancy_policy))))
        if twamp_server_policy is not None:
            child_configs.append(dict(fabricRsTwampServerPol=dict(attributes=dict(tnTwampServerPolName=twamp_server_policy))))
        if twamp_responder_policy is not None:
            child_configs.append(dict(fabricRsTwampResponderPol=dict(attributes=dict(tnTwampResponderPolName=twamp_responder_policy))))
        if node_control_policy is not None:
            child_configs.append(dict(fabricRsNodeCtrl=dict(attributes=dict(tnFabricNodeControlName=node_control_policy))))
        if analytics_cluster and analytics_name:
            analytics_tdn = "uni/fabric/analytics/cluster-{0}/cfgsrv-{1}".format(analytics_cluster, analytics_name)
            child_configs.append(dict(fabricRsNodeCfgSrv=dict(attributes=dict(tDn=analytics_tdn))))

        aci.payload(
            aci_class=aci_class,
            class_config=dict(
                name=name,
                descr=description,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
