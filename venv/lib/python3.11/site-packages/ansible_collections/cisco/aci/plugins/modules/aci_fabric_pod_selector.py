#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2023, Tim Cragg (@timcragg) <timcragg@cisco.com>
# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_pod_selector
short_description: Manage Fabric Pod Selectors (fabric:PodS)
description:
- Manage Fabric Pod Selectors on Cisco ACI fabrics.
options:
  pod_profile:
    description:
    - The name of the Pod Profile that contains the Selector.
    type: str
  name:
    description:
    - The name of the Pod Selector.
    type: str
    aliases: [ selector, pod_selector ]
  description:
    description:
    - The description for the Fabric Pod Selector.
    type: str
    aliases: [ descr ]
  type:
    description:
    - The type of the Pod Selector.
    type: str
    choices: [ all, range ]
  blocks:
    description:
    - The pod id(s) associated with the Pod Selector.
    - Existing blocks will be removed when they are not matching provided blocks.
    - A comma-separated string of pod ids or ranges of pod ids. (ex. 1,3-4)
    type: str
    aliases: [ pod_id, pod_id_range ]
  policy_group:
    description:
    - The Fabric Policy Group to bind to this Pod Selector.
    - Provide an empty string C("") to remove the Fabric Policy Group binding.
    type: str
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
- The C(pod_profile) must exist before using this module in your playbook.
- The M(cisco.aci.aci_fabric_pod_profile) module can be used to create the C(pod_profile).
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabric:PodS).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new pod selector with type all
  cisco.aci.aci_fabric_pod_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_profile: default
    name: ans_pod_selector
    type: all
    policy_group: ansible_policy_group
    state: present
  delegate_to: localhost

- name: Add a new pod selector with type range and blocks
  cisco.aci.aci_fabric_pod_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_profile: default
    name: ans_pod_selector
    type: range
    blocks: 1,3-4
    policy_group: ansible_policy_group
    state: present
  delegate_to: localhost

- name: Remove a policy_group from an existing pod selector
  cisco.aci.aci_fabric_pod_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_profile: default
    type: all
    name: ans_pod_selector
    policy_group: ""
    state: present
  delegate_to: localhost

- name: Remove a pod selector type all
  cisco.aci.aci_fabric_pod_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_profile: default
    type: all
    name: ans_pod_selector
    state: absent
  delegate_to: localhost

- name: Remove a pod selector type range
  cisco.aci.aci_fabric_pod_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_profile: default
    type: range
    name: ans_pod_selector
    state: absent
  delegate_to: localhost

- name: Query a pod selector
  cisco.aci.aci_fabric_pod_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_profile: default
    name: ans_pod_selector
    type: all
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all pod selectors
  cisco.aci.aci_fabric_pod_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
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

import binascii
import os

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible_collections.cisco.aci.plugins.module_utils.constants import FABRIC_POD_SELECTOR_TYPE_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
        pod_profile=dict(type="str"),
        name=dict(type="str", aliases=["selector", "pod_selector"]),
        type=dict(type="str", choices=["all", "range"]),
        blocks=dict(type="str", aliases=["pod_id", "pod_id_range"]),
        policy_group=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["pod_profile", "name", "type"]],
            ["state", "present", ["pod_profile", "name", "type"]],
        ],
    )

    aci = ACIModule(module)

    name_alias = module.params.get("name_alias")
    pod_profile = module.params.get("pod_profile")
    name = module.params.get("name")
    policy_group = module.params.get("policy_group")
    description = module.params.get("description")
    selector_type = FABRIC_POD_SELECTOR_TYPE_MAPPING.get(module.params.get("type"))
    blocks = [i.strip().split("-") for i in module.params.get("blocks").split(",")] if module.params.get("blocks") else []
    state = module.params.get("state")

    if state == "present" and selector_type == "range" and not blocks:
        module.fail_json(msg="The 'blocks' parameter is required when the 'type' parameter is set to 'range' and 'state' parameter is set to 'present'.")

    child_classes = ["fabricRsPodPGrp", "fabricPodBlk"]

    aci.construct_url(
        root_class=dict(
            aci_class="fabricPodP",
            aci_rn="fabric/podprof-{0}".format(pod_profile),
            module_object=pod_profile,
            target_filter={"name": pod_profile},
        ),
        subclass_1=dict(
            aci_class="fabricPodS",
            aci_rn="pods-{0}-typ-{1}".format(name, selector_type),
            module_object=name,
            target_filter={"name": name, "type": selector_type},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []

        if policy_group is not None:
            child_configs.append(
                {
                    "fabricRsPodPGrp": {
                        "attributes": {"status": "deleted"} if policy_group == "" else {"tDn": "uni/fabric/funcprof/podpgrp-{0}".format(policy_group)}
                    }
                }
            )

        if blocks:
            if isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("fabricPodS", {}).get("children", {}):
                    if child.get("fabricPodBlk"):
                        from_ = child.get("fabricPodBlk").get("attributes").get("from_")
                        to_ = child.get("fabricPodBlk").get("attributes").get("to_")
                        if [from_, to_] in blocks:
                            blocks.remove([from_, to_])
                        elif (from_ == to_) and [from_] in blocks:
                            blocks.remove([from_])
                        else:
                            child_configs.append(
                                {
                                    "fabricPodBlk": {
                                        "attributes": {
                                            "dn": "uni/fabric/podprof-{0}/pods-{1}-typ-{2}/podblk-{3}".format(
                                                pod_profile, name, selector_type, child.get("fabricPodBlk").get("attributes").get("name")
                                            ),
                                            "status": "deleted",
                                        }
                                    }
                                }
                            )

            for block in blocks:
                child_configs.append(
                    {
                        "fabricPodBlk": {
                            "attributes": {
                                "name": binascii.b2a_hex(os.urandom(8)).decode("utf-8"),
                                "from_": block[0],
                                "to_": block[1] if len(block) > 1 else block[0],
                            }
                        }
                    }
                )

        aci.payload(
            aci_class="fabricPodS",
            class_config=dict(
                name=name,
                descr=description,
                nameAlias=name_alias,
                type=selector_type,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="fabricPodS")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
