#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}


DOCUMENTATION = r"""
---
module: aci_esg_tag_selector
short_description: Manage ESG Tag Selectors (fv:TagSelector)
description:
- Manage Endpoint Security Groups Tag Selectors on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of the tenant.
    type: str
    aliases: [ tenant_name ]
  ap:
    description:
    - The name of the application profile.
    type: str
    aliases: [ app_profile, app_profile_name ]
  esg:
    description:
    - Name of the Endpoint Security Group.
    type: str
    aliases: [ esg_name ]
  name:
    description:
    - ESG Tag Selector Key Name
    type: str
    aliases: [ match_key ]
  operator:
    description:
    - C(equals) is the default operator type of the ESG Tag Selector.
    - C(contains) is used to match values partially.
    - C(regex) allows to pass patterns values.
    type: str
    choices: [ contains, equals, regex ]
    aliases: [ value_operator ]
  match_value:
    description:
    - Value filed of the ESG Tag Selector.
    type: str
  description:
    description:
    - Description of the ESG Tag Selector.
    type: str
    aliases: [ tag_selector_description ]
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

seealso:
- module: cisco.aci.aci_esg
- name: Manage Endpoint Security Groups (ESGs) objects (fv:ESg)
  description: Manage Endpoint Security Groups (ESGs) on Cisco ACI fabrics.
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sabari Jaganathan (@sajagana)
"""

EXAMPLES = r"""
- name: Add a new Tag Selector
  cisco.aci.aci_esg_tag_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: production_ap
    esg: web_esg
    name: tag-selector-key
    match_value: tag-selector-value
    description: tag-selector-description
    state: present
  delegate_to: localhost

- name: Add list of Tag Selectors
  cisco.aci.aci_esg_tag_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: production_ap
    esg: web_esg
    name: "{{ item.key }}"
    match_value: "{{ item.value }}"
    description: "{{ item.description }}"
    state: present
  delegate_to: localhost
  with_items:
    - {key: tag_selector_key_0, value: tag_selector_value_0, description: tag_selector_description_0}
    - {key: tag_selector_key_1, value: tag_selector_value_1, description: tag_selector_description_1}

- name: Query all Tag Selectors
  cisco.aci.aci_esg_tag_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Query all Tag Selectors with name and value
  cisco.aci.aci_esg_tag_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: tag-selector-key
    match_value: tag-selector-value
    state: query
  delegate_to: localhost

- name: Remove a Tag Selectors
  cisco.aci.aci_esg_tag_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    ap: production_ap
    esg: web_esg
    name: tag-selector-key
    match_value: tag-selector-value
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
        tenant=dict(type="str", aliases=["tenant_name"]),
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),
        esg=dict(type="str", aliases=["esg_name"]),
        name=dict(type="str", aliases=["match_key"]),  # ESG Tag Selector key name
        operator=dict(type="str", choices=["contains", "equals", "regex"], aliases=["value_operator"]),  # ESG Tag Selector operator type
        match_value=dict(type="str"),  # ESG Tag Selector match value
        description=dict(type="str", aliases=["tag_selector_description"]),
        state=dict(
            type="str",
            default="present",
            choices=["absent", "present", "query"],
        ),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "ap", "esg", "name", "match_value"]],
            ["state", "present", ["tenant", "ap", "esg", "name", "match_value"]],
        ],
    )

    aci = ACIModule(module)
    tenant = module.params.get("tenant")
    ap = module.params.get("ap")
    esg = module.params.get("esg")
    name = module.params.get("name")
    operator = module.params.get("operator")
    match_value = module.params.get("match_value")
    description = module.params.get("description")
    state = module.params.get("state")

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
            aci_class="fvESg",
            aci_rn="esg-{0}".format(esg),
            module_object=esg,
            target_filter={"name": esg},
        ),
        subclass_3=dict(
            aci_class="fvTagSelector",
            aci_rn="tagselectorkey-[{0}]-value-[{1}]".format(name, match_value),
            module_object=name,
            target_filter={"matchKey": name, "matchValue": match_value},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fvTagSelector",
            class_config=dict(
                matchKey=name,
                matchValue=match_value,
                valueOperator=operator,
                descr=description,
            ),
        )

        aci.get_diff(aci_class="fvTagSelector")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
