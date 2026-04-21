#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Akini Ross <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_access_span_src_group_src
short_description: Manage Access SPAN sources (span:Src)
description:
- Manage Access SPAN sources on Cisco ACI fabrics.
options:
  description:
    description:
    - The description for Access SPAN source.
    type: str
    aliases: [ descr ]
  source_group:
    description:
    - The name of the Access SPAN source group.
    type: str
    aliases: [ src_group ]
  source:
    description:
    - The name of the Access SPAN source.
    type: str
    aliases: [ name, src ]
  direction:
    description:
    - The direction of the SPAN source.
    - The APIC defaults to C(both) when unset during creation.
    type: str
    choices: [ incoming, outgoing, both ]
  filter_group:
    description:
    - The name of the Access SPAN filter group to associate with the source.
    type: str
  drop_packets:
    description:
    - Enable SPAN for only dropped packets.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  epg:
    description:
    - The SPAN source EPG details.
    - The I(epg) and I(routed_outside) cannot be configured simultaneously.
    type: dict
    suboptions:
      tenant:
        description:
        - The name of the SPAN source Tenant.
        type: str
        required: true
        aliases: [ tenant_name ]
      ap:
        description:
        - The name of the SPAN source AP.
        type: str
        required: true
        aliases: [ ap_name, app_profile, app_profile_name ]
      epg:
        description:
        - The name of the SPAN source EPG.
        type: str
        required: true
        aliases: [ epg_name ]
  routed_outside:
    description:
    - The Routed Outside details.
    - The I(epg) and I(routed_outside) cannot be configured simultaneously.
    type: dict
    suboptions:
      tenant:
        description:
        - The name of the SPAN source Tenant.
        type: str
        aliases: [ tenant_name ]
      l3out:
        description:
        - The name of the SPAN source L3Out.
        type: str
        aliases: [ l3out_name ]
      encap:
        description:
        - The VLAN associated with this Routed Outside.
        type: int
        aliases: [ vlan, vlan_id, encap_id ]
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
- The I(filter_group) and I(source_group) must exist before using this module in your playbook.
  The M(cisco.aci.aci_access_span_filter_group) and M(cisco.aci.aci_access_span_src_group) modules can be used for this.
seealso:
- module: cisco.aci.aci_access_span_filter_group
- module: cisco.aci.aci_access_span_src_group
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_ap
- module: cisco.aci.aci_epg
- module: cisco.aci.aci_l3out
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(span:Src).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Create a Access SPAN source
  cisco.aci.aci_access_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
    source: my_source
    state: present
  delegate_to: localhost

- name: Delete a Access SPAN source
  cisco.aci.aci_access_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
    source: my_source
    state: absent
  delegate_to: localhost

- name: Query all Access SPAN sources
  cisco.aci.aci_access_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific Access SPAN source
  cisco.aci.aci_access_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
    source: my_source
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible_collections.cisco.aci.plugins.module_utils.constants import SPAN_DIRECTION_MAP


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        source_group=dict(type="str", aliases=["src_group"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        source=dict(type="str", aliases=["name", "src"]),  # Not required for querying all objects
        direction=dict(type="str", choices=list(SPAN_DIRECTION_MAP.keys())),
        filter_group=dict(type="str"),
        drop_packets=dict(type="bool"),
        epg=dict(
            type="dict",
            options=dict(
                epg=dict(type="str", required=True, aliases=["epg_name"]),
                ap=dict(type="str", required=True, aliases=["ap_name", "app_profile", "app_profile_name"]),
                tenant=dict(type="str", required=True, aliases=["tenant_name"]),
            ),
        ),
        routed_outside=dict(
            type="dict",
            options=dict(
                encap=dict(type="int", aliases=["vlan", "vlan_id", "encap_id"]),
                l3out=dict(type="str", aliases=["l3out_name"]),
                tenant=dict(type="str", aliases=["tenant_name"]),
            ),
        ),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["source_group", "source"]],
            ["state", "present", ["source_group", "source"]],
        ],
        mutually_exclusive=[
            ("epg", "routed_outside"),
        ],
    )

    aci = ACIModule(module)

    description = module.params.get("description")
    source_group = module.params.get("source_group")
    source = module.params.get("source")
    direction = module.params.get("direction")
    filter_group = module.params.get("filter_group")
    drop_packets = module.params.get("drop_packets")
    epg = module.params.get("epg")
    routed_outside = module.params.get("routed_outside")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    if filter_group and drop_packets:
        module.fail_json(msg="Setting 'drop_packets' to 'true' is not allowed when 'filter_group' is configured on the source.")
    elif epg and drop_packets:
        module.fail_json(msg="Setting 'drop_packets' to 'true' is not allowed when 'epg' is configured on the source.")
    elif routed_outside and drop_packets:
        module.fail_json(msg="Setting 'drop_packets' to 'true' is not allowed when 'routed_outside' is configured on the source.")

    aci.construct_url(
        root_class=dict(
            aci_class="infra",
            aci_rn="infra",
        ),
        subclass_1=dict(
            aci_class="spanSrcGrp",
            aci_rn="srcgrp-{0}".format(source_group),
            module_object=source_group,
            target_filter={"name": source_group},
        ),
        subclass_2=dict(
            aci_class="spanSrc",
            aci_rn="src-{0}".format(source),
            module_object=source,
            target_filter={"name": source},
        ),
        child_classes=["spanRsSrcToFilterGrp", "spanRsSrcToEpg", "spanRsSrcToL3extOut"],
    )

    aci.get_existing()

    if state == "present":
        # Create new child configs payload
        child_configs = []
        filter_group_tdn = epg_dn = l3ext_out_dn = None

        if filter_group:
            filter_group_tdn = "uni/infra/filtergrp-{0}".format(filter_group)
            child_configs.append({"spanRsSrcToFilterGrp": {"attributes": {"tDn": filter_group_tdn}}})
        if epg:
            epg_dn = "uni/tn-{0}/ap-{1}/epg-{2}".format(epg.get("tenant"), epg.get("ap"), epg.get("epg"))
            child_configs.append({"spanRsSrcToEpg": {"attributes": {"tDn": epg_dn}}})
        elif routed_outside:
            # encap is set to unknown when not provided to ensure change is executed and detected properly on update
            encap = "vlan-{0}".format(routed_outside.get("encap")) if routed_outside.get("encap") else "unknown"
            if routed_outside.get("tenant") and routed_outside.get("l3out"):
                l3ext_out_dn = "uni/tn-{0}/out-{1}".format(routed_outside.get("tenant"), routed_outside.get("l3out"))
            else:
                # tDn is set to "" when not provided to ensure change is executed and detected properly on update
                l3ext_out_dn = ""
            child_configs.append({"spanRsSrcToL3extOut": {"attributes": {"encap": encap, "tDn": l3ext_out_dn}}})

        # Validate if existing and remove child objects when do not match provided configuration
        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            # Commented validate code to avoid making additional API request which is handled by APIC error
            # Keeping for informational purposes
            # Validate drop_packets are set on parent correctly
            # if aci.api_call("GET", "{0}/rssrcGrpToFilterGrp.json".format(source_group_path)) != [] and drop_packets:
            #     module.fail_json(msg="It is not allowed to configure 'drop_packets: true' when a filter group is configured on the source group.")

            source_path = "/api/mo/uni/infra/srcgrp-{0}/src-{1}".format(source_group, source)
            for child in aci.existing[0].get("spanSrc", {}).get("children", {}):
                if child.get("spanRsSrcToFilterGrp") and child.get("spanRsSrcToFilterGrp").get("attributes").get("tDn") != filter_group_tdn:
                    # Appending to child_config list not possible because of APIC Error 103: child (Rn) of class spanRsSrcGrpToFilterGrp is already attached.
                    # A seperate delete request to dn of the spanRsSrcGrpToFilterGrp is needed to remove the object prior to adding to child_configs.
                    # Failed child_config is displayed in below:
                    #
                    # child_configs.append(
                    #     {
                    #         "spanRsSrcGrpToFilterGrp": {
                    #             "attributes": {
                    #                 "dn": "uni/infra/srcgrp-{0}/src-{1}/rssrcGrpToFilterGrp".format(source_group, source),
                    #                 "status": "deleted",
                    #             }
                    #         }
                    #     }
                    # )
                    aci.api_call("DELETE", "{0}/rssrcToFilterGrp.json".format(source_path))
                elif child.get("spanRsSrcToEpg") and child.get("spanRsSrcToEpg").get("attributes").get("tDn") != epg_dn:
                    # Appending to child_config list not possible because of APIC Error 103: child (Rn) of class spanRsSrcToEpg is already attached.
                    aci.api_call("DELETE", "{0}/rssrcToEpg.json".format(source_path))
                elif child.get("spanRsSrcToL3extOut") and child.get("spanRsSrcToL3extOut").get("attributes").get("tDn") != l3ext_out_dn:
                    # Appending to child_config list not possible because of APIC Error 103: child (Rn) of class spanRsSrcToL3extOut is already attached.
                    aci.api_call("DELETE", "{0}/rssrcToL3extOut.json".format(source_path))

        aci.payload(
            aci_class="spanSrc",
            class_config=dict(
                descr=description,
                name=source,
                dir=SPAN_DIRECTION_MAP.get(direction),
                spanOnDrop=aci.boolean(drop_packets),
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="spanSrc")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
