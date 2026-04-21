#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Dag Wieers (@dagwieers)
# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2025, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_tenant_action_rule_profile
short_description: Manage action rule profiles (rtctrl:AttrP)
description:
- Manage action rule profiles on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of the tenant.
    type: str
    aliases: [ tenant_name ]
  action_rule:
    description:
    - The name of the action rule profile.
    type: str
    aliases: [action_rule_name, name ]
  set_community:
    description:
    - The set action rule based on communities.
    - To delete this attribute, pass an empty dictionary.
    type: dict
    suboptions:
      community:
        description:
        - The community value.
        type: str
      criteria:
        description:
        - The community criteria.
        - The option to append or replace the community value.
        type: str
        choices: [ append, replace, none ]
  set_dampening:
    description:
    - The set action rule based on dampening.
    - To delete this attribute, pass an empty dictionary.
    type: dict
    suboptions:
      half_life:
        description:
        - The half life value (minutes).
        type: int
      max_suppress_time:
        description:
        - The maximum suppress time value (minutes).
        type: int
      reuse:
        description:
        - The reuse limit value.
        type: int
      suppress:
        description:
        - The suppress limit value.
        type: int
  set_next_hop:
    description:
    - The set action rule based on the next hop address.
    - To delete this attribute, pass an empty string.
    type: str
  next_hop_propagation:
    description:
    - The set action rule based on nexthop unchanged configuration.
    - Can not be configured along with C(set_route_tag).
    - Can not be configured for APIC version 4.2 and prior.
    - The APIC defaults to C(false) when unset.
    type: bool
  multipath:
    description:
    - Set action rule based on set redistribute multipath configuration.
    - Can not be configured along with C(set_route_tag).
    - Can not be configured for APIC version 4.2 and prior.
    - The APIC defaults to C(false) when unset.
    type: bool
  set_preference:
    description:
    - The set action rule based on preference.
    - To delete this attribute, pass an empty string.
    type: str
  set_metric:
    description:
    - The set action rule based on metric.
    - To delete this attribute, pass an empty string.
    type: str
  set_metric_type:
    description:
    - The set action rule based on a metric type.
    - To delete this attribute, pass an empty string.
    type: str
    choices: [ ospf_type_1, ospf_type_2, "" ]
  set_route_tag:
    description:
    - The set action rule based on route tag.
    - Can not be configured along with C(next_hop_propagation) and C(multipath).
    - To delete this attribute, pass an empty string.
    type: str
  set_weight:
    description:
    - The set action rule based on weight.
    - To delete this attribute, pass an empty string.
    type: str
  set_communities:
    description:
    - List of additional communities to add to the action rule profile using the append criteria.
    - Providing an empty list O(set_communities=[]) will remove all communities.
    - This is only supported in Cisco ACI Release 6.0(2) and higher.
    type: list
    elements: dict
    suboptions:
      community:
        description:
        - The community value (e.g., no-advertise, no-export, or regular:as2-nn2:4:15).
        type: str
        required: true
      description:
        description:
        - Description for the community.
        type: str
        aliases: [ descr ]
  set_as_path:
    description:
    - List of Autonomous System (AS) path prepend configurations.
    - Providing an empty list O(set_as_path=[]) will remove all AS path configurations.
    - This is only supported in Cisco ACI Release 6.0(2) and higher.
    type: list
    elements: dict
    suboptions:
      criteria:
        description:
        - The AS path criteria.
        type: str
        choices: [ prepend, prepend-last-as ]
      last_num:
        description:
        - Number of times to prepend the last AS.
        - Only applicable when criteria is prepend-last-as.
        type: int
      asns:
        description:
        - List of ASNs to prepend.
        - Only applicable when criteria is prepend.
        type: list
        elements: dict
        suboptions:
          asn:
            description:
            - The ASN to prepend.
            type: str
            required: true
          order:
            description:
            - The order of the ASN in the prepend list.
            type: int
            required: true
  set_policy_tag:
    description:
    - The set action rule based on policy tag (External EPG or ESG).
    - Providing an empty dictionary O(set_policy_tag={}) will remove this attribute.
    - Either External EPG (l3out and external_epg) or ESG (ap and esg) must be configured, but not both.
    - This is only supported in Cisco ACI Release 6.0(2) and higher.
    type: dict
    suboptions:
      l3out:
        description:
        - The name of the L3Out.
        - Required together with C(external_epg).
        - Mutually exclusive with C(ap) and C(esg).
        type: str
      external_epg:
        description:
        - The name of the External EPG.
        - Required together with C(l3out).
        - Mutually exclusive with C(ap) and C(esg).
        type: str
        aliases: [ extepg, inst_p ]
      ap:
        description:
        - The name of the Application Profile.
        - Required together with C(esg).
        - Mutually exclusive with C(l3out) and C(external_epg).
        type: str
        aliases: [ app_profile ]
      esg:
        description:
        - The name of the Endpoint Security Group (ESG).
        - Required together with C(ap).
        - Mutually exclusive with C(l3out) and C(external_epg).
        type: str
  description:
    description:
    - The description for the action rule profile.
    type: str
    aliases: [ descr ]
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

notes:
- The C(tenant) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(rtctrl:AttrP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dag Wieers (@dagwieers)
- Tim Cragg (@timcragg)
- Gaspard Micol (@gmicol)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Create a action rule profile (with External EPG policy tag)
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
    set_preference: 100
    set_weight: 100
    set_metric: 100
    set_metric_type: ospf_type_1
    set_next_hop: 1.1.1.1
    next_hop_propagation: true
    multipath: true
    set_community:
      community: no-advertise
      criteria: replace
    set_dampening:
      half_life: 10
      reuse: 1
      suppress: 10
      max_suppress_time: 100
    set_communities:
      - community: no-advertise
        description: test
      - community: no-export
        description: test2
    set_as_path:
      - criteria: prepend
        asns:
          - asn: "65001"
            order: 0
          - asn: "65002"
            order: 1
      - criteria: prepend-last-as
        last_num: 4
    set_policy_tag:
      l3out: test
      external_epg: test
    state: present
  delegate_to: localhost

- name: Create a action rule profile (with ESG policy tag)
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: Test
    set_communities:
      - community: no-advertise
        description: test
      - community: no-export
        description: test2
    set_as_path:
      - criteria: prepend
        asns:
          - asn: "65001"
            order: 0
          - asn: "65002"
            order: 1
      - criteria: prepend-last-as
        last_num: 4
    set_policy_tag:
      ap: ap
      esg: test
    state: present
  delegate_to: localhost

- name: Delete action rule profile's children
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
    set_preference: ""
    set_weight: ""
    set_metric: ""
    set_metric_type: ""
    set_next_hop: ""
    next_hop_propagation: false
    multipath: false
    set_community: {}
    set_dampening: {}
    set_communities: []
    set_as_path: []
    set_policy_tag: {}
    state: present
  delegate_to: localhost

- name: Delete an action rule profile
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
    state: absent
  delegate_to: localhost

- name: Query all action rule profiles
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific action rule profile
  cisco.aci.aci_tenant_action_rule_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    action_rule: my_action_rule
    tenant: prod
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
    aci_annotation_spec,
    action_rule_set_comm_spec,
    action_rule_set_dampening_spec,
)
from ansible_collections.cisco.aci.plugins.module_utils.constants import MATCH_ACTION_RULE_SET_METRIC_TYPE_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        action_rule=dict(type="str", aliases=["action_rule_name", "name"]),  # Not required for querying all objects
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        set_community=dict(type="dict", options=action_rule_set_comm_spec()),
        set_dampening=dict(type="dict", options=action_rule_set_dampening_spec()),
        set_next_hop=dict(type="str"),
        next_hop_propagation=dict(type="bool"),
        multipath=dict(type="bool"),
        set_preference=dict(type="str"),
        set_metric=dict(type="str"),
        set_metric_type=dict(type="str", choices=["ospf_type_1", "ospf_type_2", ""]),
        set_route_tag=dict(type="str"),
        set_weight=dict(type="str"),
        set_communities=dict(
            type="list",
            elements="dict",
            options=dict(
                community=dict(type="str", required=True),
                description=dict(type="str", aliases=["descr"]),
            ),
        ),
        set_as_path=dict(
            type="list",
            elements="dict",
            options=dict(
                criteria=dict(type="str", choices=["prepend", "prepend-last-as"]),
                last_num=dict(type="int"),
                asns=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        asn=dict(type="str", required=True),
                        order=dict(type="int", required=True),
                    ),
                ),
            ),
        ),
        set_policy_tag=dict(
            type="dict",
            options=dict(
                l3out=dict(type="str"),
                external_epg=dict(type="str", aliases=["extepg", "inst_p"]),
                ap=dict(type="str", aliases=["app_profile"]),
                esg=dict(type="str"),
            ),
            mutually_exclusive=[
                ["l3out", "ap"],
                ["l3out", "esg"],
                ["external_epg", "ap"],
                ["external_epg", "esg"],
            ],
            required_together=[
                ["l3out", "external_epg"],
                ["ap", "esg"],
            ],
        ),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["action_rule", "tenant"]],
            ["state", "present", ["action_rule", "tenant"]],
        ],
    )

    action_rule = module.params.get("action_rule")
    description = module.params.get("description")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)

    # This dict contains the name of the child classes as well as the corresping attribute input (and attribute name if the input is a string)
    # this dict is deviating from normal child classes list structure in order to determine which child classes should be created, modified, deleted or ignored.
    child_classes = dict(
        rtctrlSetComm=dict(attribute_input=module.params.get("set_community")),
        rtctrlSetDamp=dict(attribute_input=module.params.get("set_dampening")),
        rtctrlSetNh=dict(attribute_input=module.params.get("set_next_hop"), attribute_name="addr"),
        rtctrlSetPref=dict(attribute_input=module.params.get("set_preference"), attribute_name="localPref"),
        rtctrlSetRtMetric=dict(attribute_input=module.params.get("set_metric"), attribute_name="metric"),
        rtctrlSetRtMetricType=dict(
            attribute_input=MATCH_ACTION_RULE_SET_METRIC_TYPE_MAPPING.get(module.params.get("set_metric_type")), attribute_name="metricType"
        ),
        rtctrlSetTag=dict(attribute_input=module.params.get("set_route_tag"), attribute_name="tag"),
        rtctrlSetWeight=dict(attribute_input=module.params.get("set_weight"), attribute_name="weight"),
    )

    # This condition deal with child classes which do not exist in APIC version 4.2 and prior.
    additional_child_classes = dict(
        rtctrlSetNhUnchanged=dict(attribute_input=module.params.get("next_hop_propagation")),
        rtctrlSetRedistMultipath=dict(attribute_input=module.params.get("multipath")),
    )
    for class_name, attribute in additional_child_classes.items():
        if attribute.get("attribute_input") is not None:
            child_classes[class_name] = attribute

    # Add new child classes which do not exist in APIC version 5.8/6.0 and prior for list-based configurations
    list_child_classes = []
    if module.params.get("set_communities") is not None:
        list_child_classes.append("rtctrlSetAddComm")
    if module.params.get("set_as_path") is not None:
        list_child_classes.append("rtctrlSetASPath")
    if module.params.get("set_policy_tag") is not None:
        list_child_classes.append("rtctrlSetPolicyTag")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="rtctrlAttrP",
            aci_rn="attr-{0}".format(action_rule),
            module_object=action_rule,
            target_filter={"name": action_rule},
        ),
        child_classes=list(child_classes.keys()) + list_child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []

        # Process existing single-value child classes
        for class_name, attribute in child_classes.items():
            attribute_input = attribute.get("attribute_input")
            # This condition enables to user to keep its previous configurations if they are not passing anything in the payload.
            if attribute_input is not None:
                # This condition checks if the attribute input is a dict and checks if all of its values are None (stored as a boolean in only_none).
                only_none = False
                if isinstance(attribute_input, dict):
                    only_none = all(value is None for value in attribute_input.values())
                # This condition checks if the child object needs to be deleted depending on the type of the corresponding attribute input (bool, str, dict).
                if (attribute_input == "" or attribute_input is False or only_none) and isinstance(aci.existing, list) and len(aci.existing) > 0:
                    for child in aci.existing[0].get("rtctrlAttrP", {}).get("children", {}):
                        if child.get(class_name):
                            child_configs.append(
                                {
                                    class_name: dict(
                                        attributes=dict(status="deleted"),
                                    ),
                                }
                            )
                # This condition checks if the child object needs to be modified or created depending on the type of the corresponding attribute input.
                elif attribute_input != "" or attribute_input is True or attribute_input != {}:
                    if class_name == "rtctrlSetComm" and isinstance(attribute_input, dict):
                        child_configs.append(
                            {
                                class_name: dict(
                                    attributes=dict(
                                        community=attribute_input.get("community"),
                                        setCriteria=attribute_input.get("criteria"),
                                    ),
                                )
                            }
                        )
                    elif class_name == "rtctrlSetDamp" and isinstance(attribute_input, dict):
                        child_configs.append(
                            {
                                class_name: dict(
                                    attributes=dict(
                                        halfLife=attribute_input.get("half_life"),
                                        maxSuppressTime=attribute_input.get("max_suppress_time"),
                                        reuse=attribute_input.get("reuse"),
                                        suppress=attribute_input.get("suppress"),
                                    ),
                                )
                            }
                        )
                    elif class_name in ["rtctrlSetNhUnchanged", "rtctrlSetRedistMultipath"]:
                        child_configs.append({class_name: dict(attributes=dict(descr=""))})
                    else:
                        child_configs.append({class_name: dict(attributes={attribute.get("attribute_name"): attribute_input})})

        # Process rtctrlSetAddComm (list of communities)
        set_communities = module.params.get("set_communities")
        if set_communities is not None:
            existing_communities = []

            # Get existing communities from APIC
            if isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("rtctrlAttrP", {}).get("children", []):
                    if child.get("rtctrlSetAddComm"):
                        existing_communities.append(child["rtctrlSetAddComm"])

            # Get list of communities from user input
            new_communities = [comm.get("community") for comm in set_communities]

            # Delete communities that are no longer in the new list
            for community_obj in existing_communities:
                existing_community = community_obj.get("attributes", {}).get("community")
                if existing_community and existing_community not in new_communities:
                    child_configs.append(
                        {
                            "rtctrlSetAddComm": dict(
                                attributes=dict(
                                    community=existing_community,
                                    status="deleted",
                                ),
                            )
                        }
                    )

            # Add new communities
            for comm in set_communities:
                child_configs.append(
                    {
                        "rtctrlSetAddComm": dict(
                            attributes=dict(
                                community=comm.get("community"),
                                descr=comm.get("description"),
                            ),
                        )
                    }
                )

        # Process rtctrlSetASPath (list of AS path configurations)
        # Process rtctrlSetASPath (list of AS path configurations)
        set_as_path = module.params.get("set_as_path")
        if set_as_path is not None:
            existing_as_paths = []

            # Get existing AS paths from APIC
            if isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("rtctrlAttrP", {}).get("children", []):
                    if child.get("rtctrlSetASPath"):
                        existing_as_paths.append(child["rtctrlSetASPath"])

            # Organize AS path configurations
            prepend_config = None
            prepend_last_as_config = None

            for as_path_config in set_as_path:
                criteria = as_path_config.get("criteria")

                if criteria == "prepend-last-as":
                    prepend_last_as_config = as_path_config
                elif criteria == "prepend":
                    prepend_config = as_path_config

            # Build list of criteria identifiers that should exist in new config
            new_criteria = []
            if prepend_config:
                new_criteria.append("prepend")
            if prepend_last_as_config:
                new_criteria.append("prepend-last-as")

            # Delete AS paths that are no longer in the new list
            for as_path_obj in existing_as_paths:
                existing_criteria = as_path_obj.get("attributes", {}).get("criteria", "")

                if existing_criteria not in new_criteria:
                    # Build deletion config based on criteria
                    if existing_criteria == "prepend-last-as":
                        child_configs.append(
                            {
                                "rtctrlSetASPath": dict(
                                    attributes=dict(
                                        criteria="prepend-last-as",
                                        status="deleted",
                                    ),
                                )
                            }
                        )
                    else:
                        child_configs.append(
                            {
                                "rtctrlSetASPath": dict(
                                    attributes=dict(
                                        criteria="prepend",
                                        status="deleted",
                                    ),
                                )
                            }
                        )

            # Add/update prepend configuration
            if prepend_config:
                asns_list = prepend_config.get("asns", [])

                # Get existing ASNs for prepend (if it exists)
                existing_prepend_asns = []
                for as_path_obj in existing_as_paths:
                    existing_criteria = as_path_obj.get("attributes", {}).get("criteria")

                    if existing_criteria == "prepend":
                        # Get existing ASN children
                        existing_asn_children = as_path_obj.get("children", [])

                        for child in existing_asn_children:
                            if child.get("rtctrlSetASPathASN"):
                                asn = child["rtctrlSetASPathASN"]["attributes"].get("asn")
                                order = child["rtctrlSetASPathASN"]["attributes"].get("order")
                                if asn and order is not None:
                                    existing_prepend_asns.append({"asn": str(asn), "order": str(order)})
                        break

                # Build list of new ASN identifiers
                new_asn_identifiers = []
                for idx, asn_config in enumerate(asns_list):
                    asn = str(asn_config.get("asn"))
                    order = asn_config.get("order")
                    order = str(order)
                    new_asn_identifiers.append({"asn": asn, "order": order})

                # Delete ASNs that are no longer in the new list
                for existing_asn in existing_prepend_asns:
                    asn_found = False
                    for new_asn in new_asn_identifiers:
                        if existing_asn["asn"] == new_asn["asn"] and existing_asn["order"] == new_asn["order"]:
                            asn_found = True
                            break

                    if not asn_found:
                        # Delete this ASN
                        child_configs.append(
                            {
                                "rtctrlSetASPath": dict(
                                    attributes=dict(criteria="prepend"),
                                    children=[
                                        {
                                            "rtctrlSetASPathASN": dict(
                                                attributes=dict(
                                                    asn=existing_asn["asn"],
                                                    order=existing_asn["order"],
                                                    status="deleted",
                                                ),
                                            )
                                        }
                                    ],
                                )
                            }
                        )

                # Add new ASNs
                asn_children = []
                for idx, asn_config in enumerate(asns_list):
                    asn = asn_config.get("asn")
                    order = asn_config.get("order")

                    asn_children.append(
                        {
                            "rtctrlSetASPathASN": dict(
                                attributes=dict(
                                    asn=str(asn),
                                    order=str(order),
                                ),
                                children=[],
                            )
                        }
                    )

                as_path_attrs = dict(criteria="prepend")
                child_configs.append({"rtctrlSetASPath": dict(attributes=as_path_attrs, children=asn_children)})

            # Add/update prepend-last-as configuration
            if prepend_last_as_config:
                last_num = prepend_last_as_config.get("last_num")

                as_path_attrs = dict(
                    criteria="prepend-last-as",
                    lastnum=str(last_num),
                )
                child_configs.append({"rtctrlSetASPath": dict(attributes=as_path_attrs, children=[])})

        # Process rtctrlSetPolicyTag (External EPG or ESG reference)
        # Only one type can be configured at a time (mutually exclusive)
        set_policy_tag = module.params.get("set_policy_tag")
        if set_policy_tag is not None:
            existing_policy_tags = []

            # Get existing policy tags from APIC
            if isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("rtctrlAttrP", {}).get("children", []):
                    if child.get("rtctrlSetPolicyTag"):
                        existing_policy_tags.append(child["rtctrlSetPolicyTag"])

            # Check if all values are None (empty dict behavior)
            all_none = all(value is None for value in set_policy_tag.values()) if set_policy_tag else True
            # If empty dict is passed (all values are None), delete all existing policy tags
            if all_none:
                if existing_policy_tags:
                    child_configs.append(
                        {
                            "rtctrlSetPolicyTag": dict(
                                attributes=dict(status="deleted"),
                            )
                        }
                    )
            else:
                # Determine which type is being configured
                l3out = set_policy_tag.get("l3out")
                external_epg = set_policy_tag.get("external_epg")
                ap = set_policy_tag.get("ap")
                esg = set_policy_tag.get("esg")

                new_target_dn = None
                new_relationship_class = None

                # External EPG configuration
                if l3out and external_epg:
                    new_target_dn = "uni/tn-{0}/out-{1}/instP-{2}".format(tenant, l3out, external_epg)
                    new_relationship_class = "rtctrlRsSetPolicyTagToInstP"
                # ESG configuration
                elif ap and esg:
                    new_target_dn = "uni/tn-{0}/ap-{1}/esg-{2}".format(tenant, ap, esg)
                    new_relationship_class = "rtctrlRsSetPolicyTagToESg"

                # If we have valid new configuration
                if new_target_dn and new_relationship_class:
                    needs_update = False

                    # Check if existing policy tag matches the new configuration
                    if existing_policy_tags:
                        existing_policy_tag = existing_policy_tags[0]
                        existing_children = existing_policy_tag.get("children", [])

                        # Check if the same relationship with same target exists
                        existing_match = False
                        for rel_child in existing_children:
                            if rel_child.get(new_relationship_class):
                                existing_target_dn = rel_child[new_relationship_class]["attributes"].get("tDn")
                                if existing_target_dn == new_target_dn:
                                    existing_match = True
                                break

                        # If existing doesn't match, we need to update
                        if not existing_match:
                            needs_update = True
                            aci.api_call(
                                "DELETE",
                                "{0}/api/mo/uni/tn-{1}/attr-{2}/sptag.json".format(aci.base_url, tenant, action_rule),
                            )
                    else:
                        # No existing policy tag, need to create
                        needs_update = True

                    # Add new policy tag configuration if update is needed
                    if needs_update:
                        policy_tag_children = [
                            {
                                new_relationship_class: dict(
                                    attributes=dict(tDn=new_target_dn),
                                    children=[],
                                )
                            }
                        ]
                        child_configs.append(
                            {
                                "rtctrlSetPolicyTag": dict(
                                    attributes=dict(),
                                    children=policy_tag_children,
                                )
                            }
                        )

        aci.payload(
            aci_class="rtctrlAttrP",
            class_config=dict(
                name=action_rule,
                descr=description,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="rtctrlAttrP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
