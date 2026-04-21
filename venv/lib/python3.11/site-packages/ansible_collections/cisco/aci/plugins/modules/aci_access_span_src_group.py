#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Akini Ross <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_access_span_src_group
short_description: Manage Access SPAN source groups (span:SrcGrp)
description:
- Manage SPAN source groups on Cisco ACI fabrics.
options:
  source_group:
    description:
    - The name of the Access SPAN source group.
    type: str
    aliases: [ name, src_group ]
  description:
    description:
    - The description for Access SPAN source group.
    type: str
    aliases: [ descr ]
  admin_state:
    description:
    - Enable C(true) or disable C(false) the SPAN sources.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  filter_group:
    description:
    - The name of the Access SPAN filter group to associate with the source group.
    type: str
  destination_group:
    description:
    - The name of the Access SPAN destination group to associate with the source group.
    type: str
    aliases: [ dst_group ]
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
- The I(filter_group) and I(destination_group) must exist before using this module in your playbook.
  The M(cisco.aci.aci_access_span_filter_group) and M(cisco.aci.aci_access_span_dst_group) modules can be used for this.
seealso:
- module: cisco.aci.aci_access_span_filter_group
- module: cisco.aci.aci_access_span_dst_group
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(span:SrcGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Create a Access SPAN source group
  cisco.aci.aci_access_span_src_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
    destination_group: my_span_dest_group
    state: present
  delegate_to: localhost

- name: Delete a Access SPAN source group
  cisco.aci.aci_access_span_src_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
    state: absent
  delegate_to: localhost

- name: Query all Access SPAN source groups
  cisco.aci.aci_access_span_src_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific Access SPAN source group
  cisco.aci.aci_access_span_src_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
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


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        source_group=dict(type="str", aliases=["name", "src_group"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        admin_state=dict(type="bool"),
        filter_group=dict(type="str"),
        destination_group=dict(type="str", aliases=["dst_group"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["source_group"]],
            ["state", "present", ["source_group", "destination_group"]],
        ],
    )

    aci = ACIModule(module)

    source_group = module.params.get("source_group")
    description = module.params.get("description")
    admin_state = aci.boolean(module.params.get("admin_state"), "enabled", "disabled")
    filter_group = module.params.get("filter_group")
    destination_group = module.params.get("destination_group")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

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
        child_classes=["spanSpanLbl", "spanRsSrcGrpToFilterGrp"],
    )

    aci.get_existing()

    if state == "present":
        # Create new child configs payload
        filter_group_tdn = "uni/infra/filtergrp-{0}".format(filter_group)
        child_configs = [{"spanSpanLbl": {"attributes": {"name": destination_group}}}]
        if filter_group:
            child_configs.append({"spanRsSrcGrpToFilterGrp": {"attributes": {"tDn": filter_group_tdn}}})

        # Validate if existing and remove child objects when do not match provided configuration
        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            for child in aci.existing[0].get("spanSrcGrp", {}).get("children", {}):
                if child.get("spanRsSrcGrpToFilterGrp") and child.get("spanRsSrcGrpToFilterGrp").get("attributes").get("tDn") != filter_group_tdn:
                    # Appending to child_config list not possible because of APIC Error 103: child (Rn) of class spanRsSrcGrpToFilterGrp is already attached.
                    # A seperate delete request to dn of the spanRsSrcGrpToFilterGrp is needed to remove the object prior to adding to child_configs.
                    # Failed child_config is displayed in below:
                    #
                    # child_configs.append(
                    #     {
                    #         "spanRsSrcGrpToFilterGrp": {
                    #             "attributes": {
                    #                 "dn": "uni/infra/srcgrp-{0}/rssrcGrpToFilterGrp".format(source_group),
                    #                 "status": "deleted",
                    #             }
                    #         }
                    #     }
                    # )
                    aci.api_call("DELETE", "/api/mo/uni/infra/srcgrp-{0}/rssrcGrpToFilterGrp.json".format(source_group))
                elif child.get("spanSpanLbl") and child.get("spanSpanLbl").get("attributes").get("name") != destination_group:
                    child_configs.append(
                        {
                            "spanSpanLbl": {
                                "attributes": {
                                    "dn": "uni/infra/srcgrp-{0}/spanlbl-{1}".format(source_group, child.get("spanSpanLbl").get("attributes").get("name")),
                                    "status": "deleted",
                                }
                            }
                        }
                    )

        aci.payload(
            aci_class="spanSrcGrp",
            class_config=dict(adminSt=admin_state, descr=description, name=source_group, nameAlias=name_alias),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="spanSrcGrp")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
