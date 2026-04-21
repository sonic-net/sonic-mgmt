#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Akini Ross <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_span_src_group_src
short_description: Manage Fabric SPAN sources (span:Src)
description:
- Manage Fabric SPAN sources on Cisco ACI fabrics.
options:
  description:
    description:
    - The description for Fabric SPAN source.
    type: str
    aliases: [ descr ]
  source_group:
    description:
    - The name of the Fabric SPAN source group.
    type: str
    aliases: [ src_group ]
  source:
    description:
    - The name of the Fabric SPAN source.
    type: str
    aliases: [ name, src ]
  direction:
    description:
    - The direction of the SPAN source.
    - The APIC defaults to C(both) when unset during creation.
    type: str
    choices: [ incoming, outgoing, both ]
  drop_packets:
    description:
    - Enable SPAN for only dropped packets.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  vrf:
    description:
    - The SPAN source VRF details.
    - The I(vrf) and I(bd) cannot be configured simultaneously.
    type: dict
    suboptions:
      tenant:
        description:
        - The name of the SPAN source Tenant.
        type: str
        required: true
        aliases: [ tenant_name ]
      vrf:
        description:
        - The name of the SPAN source VRF.
        type: str
        required: true
        aliases: [ vrf_name ]
  bd:
    description:
    - The SPAN source BD details.
    - The I(vrf) and I(bd) cannot be configured simultaneously.
    type: dict
    suboptions:
      tenant:
        description:
        - The name of the SPAN source Tenant.
        type: str
        required: true
        aliases: [ tenant_name ]
      bd:
        description:
        - The name of the SPAN source BD.
        type: str
        required: true
        aliases: [ bd_name, bridge_domain ]
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
- The I(source_group) must exist before using this module in your playbook.
  The M(cisco.aci.aci_fabric_span_src_group) module can be used for this.
seealso:
- module: cisco.aci.aci_fabric_span_src_group
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_vrf
- module: cisco.aci.aci_bd
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(span:Src).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Create a Fabric SPAN source
  cisco.aci.aci_fabric_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
    source: my_source
    state: present
  delegate_to: localhost

- name: Create a Fabric SPAN source with bd
  cisco.aci.aci_fabric_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
    source: my_source
    bd:
      tenant: my_tenant
      bd: my_bd
    state: present
  delegate_to: localhost

- name: Create a Fabric SPAN source with vrf
  cisco.aci.aci_fabric_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
    source: my_source
    vrf:
      tenant: my_tenant
      vrf: my_vrf
    state: present
  delegate_to: localhost

- name: Delete a Fabric SPAN source
  cisco.aci.aci_fabric_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    source_group: my_span_source_group
    source: my_source
    state: absent
  delegate_to: localhost

- name: Query all Fabric SPAN sources
  cisco.aci.aci_fabric_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific Fabric SPAN source
  cisco.aci.aci_fabric_span_src_group_src:
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
        drop_packets=dict(type="bool"),
        vrf=dict(
            type="dict",
            options=dict(
                vrf=dict(type="str", required=True, aliases=["vrf_name"]),
                tenant=dict(type="str", required=True, aliases=["tenant_name"]),
            ),
        ),
        bd=dict(
            type="dict",
            options=dict(
                bd=dict(type="str", required=True, aliases=["bd_name", "bridge_domain"]),
                tenant=dict(type="str", required=True, aliases=["tenant_name"]),
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
            ("vrf", "bd"),
        ],
    )

    aci = ACIModule(module)

    description = module.params.get("description")
    source_group = module.params.get("source_group")
    source = module.params.get("source")
    direction = module.params.get("direction")
    drop_packets = module.params.get("drop_packets")
    vrf = module.params.get("vrf")
    bd = module.params.get("bd")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    if vrf and drop_packets:
        module.fail_json(msg="It is not allowed to configure 'drop_packets: true' when 'vrf' is configured on the source.")
    elif bd and drop_packets:
        module.fail_json(msg="It is not allowed to configure 'drop_packets: true' when 'bd' is configured on the source.")

    aci.construct_url(
        root_class=dict(
            aci_class="fabric",
            aci_rn="fabric",
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
        child_classes=["spanRsSrcToCtx", "spanRsSrcToBD"],
    )

    aci.get_existing()

    if state == "present":
        # Create new child configs payload
        child_configs = []
        vrf_dn = bd_dn = None

        if vrf:
            vrf_dn = "uni/tn-{0}/ctx-{1}".format(vrf.get("tenant"), vrf.get("vrf"))
            child_configs.append({"spanRsSrcToCtx": {"attributes": {"tDn": vrf_dn}}})
        elif bd:
            bd_dn = "uni/tn-{0}/BD-{1}".format(bd.get("tenant"), bd.get("bd"))
            child_configs.append({"spanRsSrcToBD": {"attributes": {"tDn": bd_dn}}})

        # Validate if existing and remove child objects when do not match provided configuration
        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            source_path = "/api/mo/uni/fabric/srcgrp-{0}/src-{1}".format(source_group, source)
            for child in aci.existing[0].get("spanSrc", {}).get("children", {}):
                if child.get("spanRsSrcToCtx") and child.get("spanRsSrcToCtx").get("attributes").get("tDn") != vrf_dn:
                    # Appending to child_config list not possible because of APIC Error 103: child (Rn) of class spanRsSrcToCtx is already attached.
                    aci.api_call("DELETE", "{0}/rssrcToCtx.json".format(source_path))
                elif child.get("spanRsSrcToBD") and child.get("spanRsSrcToBD").get("attributes").get("tDn") != bd_dn:
                    # Appending to child_config list not possible because of APIC Error 103: child (Rn) of class spanRsSrcToBD is already attached.
                    aci.api_call("DELETE", "{0}/rssrcToBD.json".format(source_path))

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
