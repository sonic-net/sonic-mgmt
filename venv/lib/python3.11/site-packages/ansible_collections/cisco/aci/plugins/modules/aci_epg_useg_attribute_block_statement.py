#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_epg_useg_attribute_block_statement
short_description: Manage EPG useg Attributes Block Statements (fv:SCrtrn)
description:
- Manage EPG useg Attributes Block Statements
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  ap:
    description:
    - The name of an existing application network profile.
    type: str
    aliases: [ app_profile, app_profile_name ]
  epg:
    description:
    - The name of an existing end point group.
    type: str
    aliases: [ epg_name ]
  parent_block_statements:
    description:
    - The list of parent block statements.
    - The order of the provided list matters, assuming the list ["A", "B"].
    - The block statement "A" will be the parent of "B"
    - The block statement "A" will be a child of the default block statement.
    - The maximum amount of parent block statements is 2.
    type: list
    elements: str
    aliases: [ blocks, parent_blocks ]
  name:
    description:
    - The name of the block statement.
    type: str
    aliases: [ block_statement, block_statement_name ]
  match:
    description:
    - The match type of the Block Statement.
    - The APIC defaults to C(any) when unset during creation.
    type: str
    choices: [ any, all ]
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

notes:
- The I(tenant), I(ap) and I(epg) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_ap) and M(cisco.aci.aci_epg) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_ap
- module: cisco.aci.aci_epg
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:SCrtrn).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross))
"""

EXAMPLES = r"""
- name: Add a new block statement
  cisco.aci.aci_epg_useg_attribute_block_statement:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    name: block_a
    state: present
  delegate_to: localhost

- name: Add a new nested block statement
  cisco.aci.aci_epg_useg_attribute_block_statement:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    parent_block_statements:
      - block_a
      - block_b
    name: block_c
    match: any
    state: present
  delegate_to: localhost

- name: Query a block statement
  cisco.aci.aci_epg_useg_attribute_block_statement:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    name: block_a
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all block statements
  cisco.aci.aci_epg_useg_attribute_block_statement:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove an existing block statement
  cisco.aci.aci_epg_useg_attribute_block_statement:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    name: block_a
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),  # Not required for querying all objects
        epg=dict(type="str", aliases=["epg_name"]),  # Not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        parent_block_statements=dict(type="list", elements="str", aliases=["parent_blocks", "blocks"]),
        name=dict(type="str", aliases=["block_statement", "block_statement_name"]),
        match=dict(type="str", choices=["any", "all"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["ap", "epg", "tenant", "name"]],
            ["state", "present", ["ap", "epg", "tenant", "name"]],
        ],
    )

    aci = ACIModule(module)

    ap = module.params.get("ap")
    epg = module.params.get("epg")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    blocks = module.params.get("parent_block_statements")
    name = module.params.get("name")
    match = module.params.get("match")

    block_statement_class = "fvSCrtrn"

    if blocks:
        if len(blocks) > 2:
            module.fail_json(msg="{0} block statements are provided but the maximum amount of parent_block_statements is 2".format(len(blocks)))
        parent_blocks_class = block_statement_class
        parent_blocks_rn = "crtrn/crtrn-{0}".format("/crtrn-".join(blocks))
        parent_blocks_name = blocks[-1]
    else:
        parent_blocks_class = "fvCrtrn"
        parent_blocks_rn = "crtrn"
        parent_blocks_name = "default"

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
            aci_class=parent_blocks_class,
            aci_rn=parent_blocks_rn,
            module_object=parent_blocks_name,
            target_filter={"name": parent_blocks_name},
        ),
        subclass_4=dict(
            aci_class=block_statement_class,
            aci_rn="crtrn-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(aci_class=block_statement_class, class_config=dict(name=name, match=match))

        aci.get_diff(aci_class=block_statement_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
