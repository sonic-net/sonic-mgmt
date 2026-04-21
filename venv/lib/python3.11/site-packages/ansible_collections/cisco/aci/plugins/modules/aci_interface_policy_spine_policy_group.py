#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Anvitha Jain <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_spine_policy_group
short_description: Manage spine access interface policy groups (infra:SpAccPortGrp)
description:
- Manage spine access interface policy groups on Cisco ACI fabrics.
options:
  policy_group:
    description:
    - The name of the spine access interface policy group.
    type: str
    aliases: [ name, policy_group_name, spine_policy_group_name ]
  description:
    description:
    - Description of the spine access interface
    type: str
    aliases: [ descr ]
  name_alias:
    description:
    - The alias of the current object. This relates to the nameAlias field in ACI.
    type: str
  link_level_policy:
    description:
    - The name of the link level policy used by the spine access interface
    type: str
    aliases: [ link_level_policy_name ]
  link_flap_policy:
    description:
    - The name of the link flap policy used by the spine access interface
    type: str
    aliases: [ link_flap_policy_name ]
  cdp_policy:
    description:
    - The name of the cdp policy used by the spine access interface
    type: str
    aliases: [ cdp_policy_name ]
  mac_sec_policy:
    description:
    - The name of the mac sec policy used by the spine access interface
    type: str
    aliases: [ mac_sec_policy_name ]
  attached_entity_profile:
    description:
    - The name of the attached entity profile used by the spine access interface
    type: str
    aliases: [ aep_name, aep ]
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
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:SpAccPortGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Anvitha Jain (@anvjain)
"""

EXAMPLES = r"""
- name: Create a Spine Interface Policy Group
  cisco.aci.aci_interface_policy_spine_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: spinepolicygroupname
    description: policygroupname description
    link_level_policy: somelinklevelpolicy
    link_flap_policy: somelinkflappolicy
    cdp_policy: somecdppolicy
    mac_sec_policy: somemacsecpolicy
    attached_entity_profile: someattachedentityprofile
    state: present
  delegate_to: localhost

- name: Query all Spine Access Port Policy Groups of type link
  cisco.aci.aci_interface_policy_spine_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific Lead Access Port Policy Group
  cisco.aci.aci_interface_policy_spine_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: spinepolicygroupname
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete an Interface policy Spine Policy Group
  cisco.aci.aci_interface_policy_spine_policy_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: spinepolicygroupname
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        policy_group=dict(type="str", aliases=["policy_group_name", "spine_policy_group_name", "name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        name_alias=dict(type="str"),
        link_level_policy=dict(type="str", aliases=["link_level_policy_name"]),
        link_flap_policy=dict(type="str", aliases=["link_flap_policy_name"]),
        cdp_policy=dict(type="str", aliases=["cdp_policy_name"]),
        mac_sec_policy=dict(type="str", aliases=["mac_sec_policy_name"]),
        attached_entity_profile=dict(type="str", aliases=["aep_name", "aep"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["policy_group"]],
            ["state", "present", ["policy_group"]],
        ],
    )

    policy_group = module.params.get("policy_group")
    description = module.params.get("description")
    name_alias = module.params.get("name_alias")
    link_level_policy = module.params.get("link_level_policy")
    link_flap_policy = module.params.get("link_flap_policy")
    cdp_policy = module.params.get("cdp_policy")
    mac_sec_policy = module.params.get("mac_sec_policy")
    attached_entity_profile = module.params.get("attached_entity_profile")
    state = module.params.get("state")

    aci = ACIModule(module)

    class_config = dict(
        name=policy_group,
        descr=description,
        nameAlias=name_alias,
    )

    child_configs = [
        dict(
            infraRsHIfPol=dict(
                attributes=dict(
                    tnFabricHIfPolName=link_level_policy,
                ),
            ),
        ),
        dict(
            infraRsLinkFlapPol=dict(
                attributes=dict(
                    tnFabricLinkFlapPolName=link_flap_policy,
                ),
            ),
        ),
        dict(
            infraRsCdpIfPol=dict(
                attributes=dict(
                    tnCdpIfPolName=cdp_policy,
                ),
            ),
        ),
        dict(
            infraRsMacsecIfPol=dict(
                attributes=dict(
                    tnMacsecIfPolName=mac_sec_policy,
                ),
            ),
        ),
    ]

    if attached_entity_profile is not None:
        child_configs.append(
            dict(
                infraRsAttEntP=dict(
                    attributes=dict(
                        tDn="uni/infra/attentp-{0}".format(attached_entity_profile),
                    ),
                ),
            )
        )

    aci.construct_url(
        root_class=dict(
            aci_class="infraSpAccPortGrp",
            aci_rn="infra/funcprof/spaccportgrp-{0}".format(policy_group),
            module_object=policy_group,
            target_filter={"name": policy_group},
        ),
        child_classes=[
            "infraRsHIfPol",
            "infraRsLinkFlapPol",
            "infraRsCdpIfPol",
            "infraRsMacsecIfPol",
            "infraRsAttEntP",
        ],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="infraSpAccPortGrp",
            class_config=class_config,
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="infraSpAccPortGrp")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
