#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Christian Kolrep <christian.kolrep@dataport.de>
# Copyright: (c) 2024, Akini Ross <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_epg_useg_attribute_simple_statement
short_description: Manage EPG useg Attributes Simple Statements (fv:DnsAttr, fv:IdGroupAttr, fv:IpAttr, fv:MacAttr, and fv:VmAttr)
description:
- Manage EPG useg Attributes Simple Statements
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
    - The order of the provided list matters, assuming the list ["A", "B", "C"].
    - The block statement "A" will be the parent of "B"
    - The block statement "A" will be a child of the default block statement.
    - The maximum amount of parent block statements is 3.
    type: list
    elements: str
    aliases: [ blocks, parent_blocks ]
  name:
    description:
    - The name of the EPG useg attribute.
    type: str
    aliases: [ useg_attribute_name ]
  type:
    description:
    - The type of the EPG useg attribute
    type: str
    required: true
    choices:
    - ip
    - mac
    - dns
    - ad_group
    - vm_custom_attr
    - vm_vmm_domain
    - vm_operating_system
    - vm_hypervisor_id
    - vm_datacenter
    - vm_id
    - vm_name
    - vm_folder
    - vm_folder_path
    - vm_vnic
    - vm_tag
    aliases: [ useg_attribute_type ]
  operator:
    description:
    - The operator of the EPG useg attribute.
    type: str
    choices: [ equals, contains, starts_with, ends_with ]
  category:
    description:
    - The name of the vmware tag category or vmware custom attribute.
    type: str
    aliases: [ custom_attribute ]
  use_subnet:
    description:
    - Whether to use the EPG subnet definition for ip.
    type: bool
  value:
    description:
    - The value of the EPG useg attribute.
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

notes:
- The I(tenant), I(ap) and I(epg) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_ap) and M(cisco.aci.aci_epg) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_ap
- module: cisco.aci.aci_epg
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:DnsAttr), B(fv:IdGroupAttr), B(fv:IpAttr), B(fv:MacAttr), and B(fv:VmAttr).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Christian Kolrep (@Christian-Kolrep)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new vmtag useg attribute in default block statement
  cisco.aci.aci_epg_useg_attribute_simple_statement:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    name: vmtagprod
    type: vmtag
    category: Environment
    operator: equals
    value: Production
    state: present
  delegate_to: localhost

- name: Add a new vmtag useg attribute in nested block statement
  cisco.aci.aci_epg_useg_attribute_simple_statement:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    name: vmtagprod
    parent_block_statements:
      - block_a
      - block_b
    type: vmtag
    category: Environment
    operator: equals
    value: Production
    state: present
  delegate_to: localhost

- name: Query a specific vmtag useg attribute in default block statement
  cisco.aci.aci_epg_useg_attribute_simple_statement:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    name: vmtagprod
    type: vmtag
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all vmtag useg attributes
  cisco.aci.aci_epg_useg_attribute_simple_statement:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
    type: vmtag
  delegate_to: localhost
  register: query_result

- name: Remove an existing vmtag useg attribute from default block statement
  cisco.aci.aci_epg_useg_attribute_simple_statement:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: anstest
    ap: anstest
    epg: anstest
    name: vmtagprod
    type: vmtag
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import USEG_ATTRIBUTE_MAPPING, OPERATOR_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),  # Not required for querying all objects
        epg=dict(type="str", aliases=["epg_name"]),  # Not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        parent_block_statements=dict(type="list", elements="str", aliases=["parent_blocks", "blocks"]),
        name=dict(type="str", aliases=["useg_attribute_name"]),
        type=dict(type="str", required=True, choices=list(USEG_ATTRIBUTE_MAPPING.keys()), aliases=["useg_attribute_type"]),
        operator=dict(type="str", choices=list(OPERATOR_MAPPING.keys())),
        category=dict(type="str", aliases=["custom_attribute"]),
        value=dict(type="str"),
        use_subnet=dict(type="bool"),
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
    attribute_type = module.params.get("type")
    value = module.params.get("value")
    operator = module.params.get("operator")
    category = module.params.get("category")
    use_subnet = aci.boolean(module.params.get("use_subnet"))

    # Excluding below classes from the module:
    # fvProtoAttr:
    #   Was used in AVS, but it is not longer in use.
    # fvUsegBDCont:
    #   Was part of a feature that allowed uSeg attributes to be applied at VRF (instead of BD) level.
    #   It has been since deprecated and we no longer allow setting the scope at fvCtrn to scope-vrf.
    #   This type of functionality has been replaced by the ESG feature.
    attribute_class = USEG_ATTRIBUTE_MAPPING[attribute_type]["attribute_class"]
    attribute_rn = USEG_ATTRIBUTE_MAPPING[attribute_type]["rn_format"].format(name)
    attribute_type = USEG_ATTRIBUTE_MAPPING[attribute_type]["attribute_type"]

    if blocks:
        if len(blocks) > 3:
            module.fail_json(msg="{0} block statements are provided but the maximum amount of parent_block_statements is 3".format(len(blocks)))
        parent_blocks_class = "fvSCrtrn"
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
            aci_class=attribute_class,
            aci_rn=attribute_rn,
            module_object=name,
            target_filter={"name": name},
        ),
    )

    aci.get_existing()

    if state == "present":
        class_config = dict(name=name)

        if attribute_class == "fvVmAttr":
            class_config.update(type=attribute_type)
            class_config.update(operator=OPERATOR_MAPPING.get(operator))
            class_config.update(value=value)
            if attribute_type == "tag":
                class_config.update(category=category)
            elif attribute_type == "custom-label":
                class_config.update(labelName=category)

        elif attribute_class == "fvIpAttr":
            class_config.update(usefvSubnet=use_subnet)
            class_config.update(ip=value)

        elif attribute_class == "fvMacAttr":
            class_config.update(mac=value.upper())

        elif attribute_class == "fvDnsAttr":
            class_config.update(filter=value)

        elif attribute_class == "fvIdGroupAttr":
            class_config.update(selector=value)

        aci.payload(aci_class=attribute_class, class_config=class_config)

        aci.get_diff(aci_class=attribute_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
