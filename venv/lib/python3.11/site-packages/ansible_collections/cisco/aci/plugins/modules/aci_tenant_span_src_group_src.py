#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Akini Ross (@akinross)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_tenant_span_src_group_src
short_description: Manage SPAN source group sources (span:Src)
description:
- Manage SPAN source group sources on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the Span source.
    type: str
  description:
    description:
    - The description for Span source.
    type: str
    aliases: [ descr ]
  src_group:
    description:
    - The name of the Span source group.
    type: str
  tenant:
    description:
    - The name of the Tenant.
    type: str
    aliases: [ tenant_name ]
  direction:
    description:
    - The direction of the SPAN source.
    type: str
    choices: [ incoming, outgoing, both ]
  src_epg:
    description:
    - The name of the Span source epg.
    type: str
    aliases: [ epg ]
  src_ap:
    description:
    - The name of the Span source ap.
    type: str
    aliases: [ ap ]
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
- The C(tenant) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(span:SrcGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Create a SPAN source
  cisco.aci.aci_tenant_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    src_group: my_span_source_group
    tenant: prod
    name: test
    direction: incoming
    src_epg: epg1
    state: present
  delegate_to: localhost

- name: Delete a SPAN source
  cisco.aci.aci_tenant_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    src_group: my_span_source_group
    tenant: prod
    name: test
    state: absent
  delegate_to: localhost

- name: Query all SPAN sources
  cisco.aci.aci_tenant_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific SPAN source
  cisco.aci.aci_tenant_span_src_group_src:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: test
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
        description=dict(type="str", aliases=["descr"]),
        direction=dict(type="str", choices=list(SPAN_DIRECTION_MAP.keys())),
        name=dict(type="str"),  # Not required for querying all objects
        src_ap=dict(type="str", aliases=["ap"]),
        src_epg=dict(type="str", aliases=["epg"]),
        src_group=dict(type="str"),  # Not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "src_group", "tenant"]],
            ["state", "present", ["name", "direction", "src_group", "tenant"]],
        ],
        required_together=[("src_ap", "src_epg")],
    )

    aci = ACIModule(module)

    description = module.params.get("description")
    direction = module.params.get("direction")
    name = module.params.get("name")
    src_ap = module.params.get("src_ap")
    src_epg = module.params.get("src_epg")
    src_group = module.params.get("src_group")
    state = module.params.get("state")
    tenant = module.params.get("tenant")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="spanSrcGrp",
            aci_rn="srcgrp-{0}".format(src_group),
            module_object=src_group,
            target_filter={"name": src_group},
        ),
        subclass_2=dict(
            aci_class="spanSrc",
            aci_rn="src-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=["spanRsSrcToEpg"],
    )

    aci.get_existing()

    if state == "present":
        tdn = None
        if src_epg:
            tdn = "uni/tn-{0}/ap-{1}/epg-{2}".format(tenant, src_ap, src_epg)

        aci.payload(
            aci_class="spanSrc",
            class_config=dict(descr=description, name=name, dir=SPAN_DIRECTION_MAP.get(direction)),
            child_configs=[{"spanRsSrcToEpg": {"attributes": {"tDn": tdn}}}],
        )

        aci.get_diff(aci_class="spanSrc")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
