#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2024, Samita Bhattacharjee (@samitab) <samitab.cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_pod_connectivity_profile
short_description: Manage Fabric External Pod Connectivity Profiles (fv:PodConnP)
description:
- Manage Fabric External Pod Connectivity Profiles on Cisco ACI fabrics.
options:
  pod_id:
    description:
    - The Pod ID associated with the Pod Connectivity Profile.
    type: int
    aliases: [ pod, pid ]
  fabric_id:
    description:
    - The Fabric ID associated with the Pod Connectivity Profile.
    type: int
    aliases: [ fabric, fid ]
  virtual_pod_id:
    description:
    - The Pod ID in the main fabric to which this I(pod_id) is associated. This property is valid only if this pod is a virtual pod.
    type: int
    aliases: [ vpod, vpod_id ]
  description:
    description:
    - The description of the Pod Connectivity Profile.
    type: str
    aliases: [ descr ]
  data_plane_tep:
    description:
    - The Data Plane TEP IPv4 address and prefix.
    - eg. 10.1.1.1/32
    type: str
    aliases: [ dp_tep ]
  unicast_tep:
    description:
    - The Unicast TEP IPv4 address and prefix.
    - eg. 10.1.1.2/32
    type: str
    aliases: [ u_tep ]
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
- This module requires an existing I(fabric_external_connection_profile).
  The module M(cisco.aci.aci_fabric_external_connection_profile) can be used for this.
seealso:
- module: cisco.aci.aci_fabric_external_connection_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:PodConnP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Add a Pod Connectivity Profile
  cisco.aci.aci_fabric_pod_connectivity_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    fabric_id: 1
    pod_id: 1
    description: First pod connectivity profile
    data_plane_tep: 10.1.1.1/32
    unicast_tep: 10.1.1.2/32
    state: present
  delegate_to: localhost

- name: Query a Pod Connectivity Profile
  cisco.aci.aci_fabric_pod_connectivity_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    fabric_id: 1
    pod_id: 1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Pod Connectivity Profiles
  cisco.aci.aci_fabric_pod_connectivity_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a Pod Connectivity Profile
  cisco.aci.aci_fabric_pod_connectivity_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    fabric_id: 1
    pod_id: 1
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
        pod_id=dict(type="int", aliases=["pod", "pid"]),
        fabric_id=dict(type="int", aliases=["fabric", "fid"]),
        virtual_pod_id=dict(type="int", aliases=["vpod", "vpod_id"]),
        description=dict(type="str", aliases=["descr"]),
        data_plane_tep=dict(type="str", aliases=["dp_tep"]),
        unicast_tep=dict(type="str", aliases=["u_tep"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["fabric_id", "pod_id"]],
            ["state", "present", ["fabric_id", "pod_id"]],
        ],
    )

    aci = ACIModule(module)

    pod_id = module.params.get("pod_id")
    fabric_id = module.params.get("fabric_id")
    virtual_pod_id = module.params.get("virtual_pod_id")
    description = module.params.get("description")
    data_plane_tep = module.params.get("data_plane_tep")
    unicast_tep = module.params.get("unicast_tep")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="fvFabricExtConnP",
            aci_rn="tn-infra/fabricExtConnP-{0}".format(fabric_id),
            module_object=fabric_id,
            target_filter={"id": fabric_id},
        ),
        subclass_1=dict(
            aci_class="fvPodConnP",
            aci_rn="podConnP-{0}".format(pod_id),
            module_object=pod_id,
            target_filter={"id": pod_id},
        ),
        child_classes=["fvIp", "fvExtRoutableUcastConnP"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []

        # Validate if existing and remove child objects when the config does not match the provided config.
        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            for child in aci.existing[0].get("fvPodConnP", {}).get("children", {}):
                if child.get("fvExtRoutableUcastConnP") and child.get("fvExtRoutableUcastConnP").get("attributes").get("addr") != unicast_tep:
                    child_configs.append(
                        {
                            "fvExtRoutableUcastConnP": {
                                "attributes": {
                                    "addr": child.get("fvExtRoutableUcastConnP").get("attributes").get("addr"),
                                    "status": "deleted",
                                }
                            }
                        }
                    )
                if child.get("fvIp") and child.get("fvIp").get("attributes").get("addr") != data_plane_tep:
                    child_configs.append(
                        {
                            "fvIp": {
                                "attributes": {
                                    "addr": child.get("fvIp").get("attributes").get("addr"),
                                    "status": "deleted",
                                }
                            }
                        }
                    )

        if unicast_tep is not None:
            child_configs.append({"fvExtRoutableUcastConnP": {"attributes": {"addr": unicast_tep}}})
        if data_plane_tep is not None:
            child_configs.append({"fvIp": {"attributes": {"addr": data_plane_tep}}})

        aci.payload(
            aci_class="fvPodConnP",
            class_config=dict(
                id=pod_id,
                assocIntersitePodId=virtual_pod_id,
                descr=description,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="fvPodConnP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
