#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022
# Marcin Woźniak (@y0rune) <y0rune@aol.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["deprecated"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
author:
  - "Marcin Wo\u017Aniak (@y0rune)"
deprecated:
  alternative: cisco.meraki.networks_switch_access_policies
  removed_in: 3.0.0
  why: Updated modules released with increased functionality
description: Module for managing a Switch Access Policies in the Meraki cloud
extends_documentation_fragment: cisco.meraki.meraki
module: meraki_ms_access_policies
options:
  access_policy_type:
    choices:
      - 802.1x
      - MAC authentication bypass
      - Hybrid authentication
    description:
      - Set type of the access policy
    type: str
  auth_method:
    choices:
      - Meraki authentication
      - my RADIUS server
    description:
      - Set authentication method in the policy.
    type: str
  data_vlan_id:
    description:
      - Set a Data VLAN ID for Critical Auth VLAN
    type: int
  guest_vlan:
    description:
      - Guest Vlan
    type: int
  host_mode:
    choices:
      - Single-Host
      - Multi-Domain
      - Multi-Host
      - Multi-Auth
    description:
      - Choose the Host Mode for the access policy.
    type: str
  name:
    description:
      - Name of Access Policy.
    type: str
  net_id:
    description:
      - ID of network.
    type: str
  net_name:
    aliases:
      - network
    description:
      - Name of a network.
    type: str
  number:
    aliases:
      - access_policy_number
    description:
      - Number of the access_policy.
    type: int
  org_id:
    description:
      - ID of organization associated to a network.
    type: str
  radius_accounting_enabled:
    description:
      - Enable or disable RADIUS accounting.
    type: bool
  radius_accounting_servers:
    description:
      - List of RADIUS servers for RADIUS accounting.
    elements: dict
    suboptions:
      host:
        description:
          - IP address or hostname of RADIUS server.
        required: true
        type: str
      port:
        description:
          - Port number RADIUS server is listening to.
        type: int
      secret:
        description:
          - RADIUS password.
        type: str
    type: list
  radius_attribute_group_policy_name:
    choices:
      - Filter-Id
      - ''
    default: ''
    description:
      - Enable that attribute for a RADIUS
    type: str
  radius_coa_enabled:
    description:
      - Enable or disable RADIUS CoA (Change of Authorization).
    type: bool
  radius_servers:
    description:
      - List of RADIUS servers.
    elements: dict
    suboptions:
      host:
        description:
          - IP address or hostname of RADIUS server.
        required: true
        type: str
      port:
        description:
          - Port number RADIUS server is listening to.
        type: int
      secret:
        description:
          - RADIUS password.
          - Setting password is not idempotent.
        type: str
    type: list
  radius_testing:
    default: true
    description:
      - Set status of testing a radius.
    type: bool
  state:
    choices:
      - absent
      - query
      - present
    default: present
    description:
      - Specifies whether SNMP information should be queried or modified.
    type: str
  suspend_port_bounce:
    default: false
    description:
      - Enable or disable the Suspend Port Bounce when RADIUS servers are unreachable.
    type: bool
  systems_management_enrollment:
    default: false
    description:
      - Set if the Systems Management Enrollemnt is enabled or disabled
    type: bool
  voice_vlan_clients:
    default: true
    description:
      - If is enabled that means Voice VLAN client require authentication
    type: bool
  voice_vlan_id:
    description:
      - Set a Voice VLAN ID for Critical Auth VLAN
    type: int
short_description: Manage Switch Access Policies in the Meraki cloud
"""

EXAMPLES = r"""
- name: Create access policy with auth_method is "Meraki authentication"
  cisco.meraki.meraki_ms_access_policies:
    auth_key: abc123
    state: present
    name: Meraki authentication policy
    auth_method: Meraki authentication
    net_name: YourNet
    org_name: YourOrg
  delegate_to: localhost
- name: Create access policy with auth_method is "my Radius Server"
  cisco.meraki.meraki_ms_access_policies:
    auth_key: abc123
    access_policy_type: 802.1x
    host_mode: Single-Host
    state: present
    name: Meraki authentication policy
    auth_method: my RADIUS server
    radius_servers:
      - host: 192.0.1.18
        port: 7890
        secret: secret123
    net_name: YourNet
    org_name: YourOrg
    radius_coa_enabled: false
    radius_accounting_enabled: false
    guest_vlan: 10
    voice_vlan_clients: false
"""

RETURN = r"""
data:
    description: List of Access Policies
    returned: success
    type: complex
    contains:
        number:
            description: Number of the Access Policy
            returned: success
            type: int
            sample: 1
        name:
            description: Name of the Access Policy
            returned: success
            type: str
            sample: Policy with 802.1x
        access_policy_type:
            description: Type of the access policy
            returned: success
            type: str
            sample: 802.1x
        guest_vlan_id:
            description: ID of the Guest Vlan
            returned: success
            type: int
            sample: 10
        host_mode:
            description: Choosen teh Host Mode for the access policy
            returned: success
            type: str
            sample: Single-Host
        radius:
            description: List of radius specific list
            returned: success
            type: complex
            contains:
                critial_auth:
                    description: Critial Auth List
                    returned: success
                    type: complex
                    contains:
                        data_vlan_id:
                            description: VLAN ID for data
                            returned: success
                            type: int
                            sample: 10
                        suspend_port_bounce:
                            description: Enable or disable suspend port bounce
                            returned: success
                            type: bool
                            sample: false
                        voice_vlan_id:
                            description: VLAN ID for voice
                            returned: success
                            type: int
                            sample: 10
                failed_auth_vlan_id:
                    description: VLAN ID when failed auth
                    returned: success
                    type: int
                    sample: 11
                re_authentication_interval:
                    description: Interval of re-authentication
                    returned: success
                    type: int
                    sample:
        radius_coa_enabled:
            description:
            - Enable or disable RADIUS CoA (Change of Authorization).
            type: bool
        radius_accounting_enabled:
            description:
            - Enable or disable RADIUS accounting.
            type: bool
        radius_accounting_servers:
            description:
            - List of RADIUS servers for RADIUS accounting.
            type: list
            elements: dict
        radius_servers:
            description:
            - List of RADIUS servers.
            type: list
            elements: dict
        radius_attribute_group_policy_name:
            description: Enable the radius group attribute
            returned: success
            type: str
            choices: [ "11", ""]
            sample: 11
        radius_testing_enabled:
            description: Enable or disable Radius Testing
            returned: success
            type: bool
            sample: true
        voice_vlan_clients:
            description: Enable or disable Voice Vlan Clients
            returned: success
            type: bool
            sample: false
"""

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import (
    MerakiModule,
    meraki_argument_spec,
)


def convert_vlan_id(vlan_id):
    if vlan_id == "":
        return None
    elif vlan_id == 0:
        return None
    elif vlan_id in range(1, 4094):
        return vlan_id


def convert_radius_attribute_group_policy_name(arg):
    if arg == "Filter-Id":
        return 11
    else:
        return ""


def main():
    argument_spec = meraki_argument_spec()

    radius_arg_spec = dict(
        host=dict(type="str", required=True),
        port=dict(type="int"),
        secret=dict(type="str", no_log=True),
    )

    argument_spec.update(
        state=dict(
            type="str",
            choices=["present", "query", "absent"],
            default="present",
        ),
        net_id=dict(type="str"),
        net_name=dict(type="str", aliases=["network"]),
        number=dict(type="int", aliases=["access_policy_number"]),
        name=dict(type="str"),
        auth_method=dict(
            type="str",
            choices=["Meraki authentication", "my RADIUS server"],
        ),
        guest_vlan=dict(type="int"),
        access_policy_type=dict(
            type="str",
            choices=[
                "802.1x",
                "MAC authentication bypass",
                "Hybrid authentication",
            ],
        ),
        systems_management_enrollment=dict(type="bool", default=False),
        radius_servers=dict(
            type="list", default=None, elements="dict", options=radius_arg_spec
        ),
        radius_testing=dict(type="bool", default="True"),
        voice_vlan_clients=dict(type="bool", default="True"),
        radius_coa_enabled=dict(type="bool"),
        radius_accounting_enabled=dict(type="bool"),
        radius_accounting_servers=dict(
            type="list", elements="dict", options=radius_arg_spec
        ),
        host_mode=dict(
            type="str",
            choices=["Single-Host", "Multi-Domain", "Multi-Host", "Multi-Auth"],
        ),
        data_vlan_id=dict(type="int"),
        voice_vlan_id=dict(type="int"),
        suspend_port_bounce=dict(type="bool", default="False"),
        radius_attribute_group_policy_name=dict(
            type="str", choices=["Filter-Id", ""], default=""
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    meraki = MerakiModule(module, function="access_policies")

    net_id = meraki.params["net_id"]
    net_name = meraki.params["net_name"]

    org_id = meraki.params["org_id"]
    org_name = meraki.params["org_name"]

    if meraki.params["net_name"] and meraki.params["net_id"]:
        meraki.fail_json(msg="net_name and net_id are mutually exclusive")

    if meraki.params["org_name"] and meraki.params["org_id"]:
        meraki.fail_json(msg="org_name and org_id are mutually exclusive")

    if net_id or net_name:
        if net_id is None:
            if org_id is None:
                org_id = meraki.get_org_id(org_name)
            nets = meraki.get_nets(org_id=org_id)
            net_id = meraki.get_net_id(net_name=net_name, data=nets)

    query_urls = {"access_policies": "/networks/{net_id}/switch/accessPolicies"}
    query_url = {
        "access_policies": "/networks/{net_id}/switch/accessPolicies/{number}"
    }
    update_url = {
        "access_policies": "/networks/{net_id}/switch/accessPolicies/{number}"
    }
    create_url = {"access_policies": "/networks/{net_id}/switch/accessPolicies"}

    meraki.url_catalog["get_all"].update(query_urls)
    meraki.url_catalog["get_one"].update(query_url)
    meraki.url_catalog["update"] = update_url
    meraki.url_catalog["create"] = create_url

    payload_auth = {
        "name": meraki.params["name"],
        "radiusServers": [],
        "radiusTestingEnabled": False,
        "radiusGroupAttribute": meraki.params[
            "radius_attribute_group_policy_name"
        ],
        "radius": {
            "criticalAuth": {
                "dataVlanId": None,
                "voiceVlanId": None,
                "suspendPortBounce": False,
            },
            "failedAuthVlanId": None,
            "reAuthenticationInterval": None,
        },
        "radiusCoaSupportEnabled": False,
        "radiusAccountingEnabled": False,
        "radiusAccountingServers": [],
        "hostMode": "Single-Host",
        "accessPolicyType": "802.1x",
        "voiceVlanClients": True,
        "systems_management_enrollment": meraki.params[
            "systems_management_enrollment"
        ],
        "guestVlanId": meraki.params["guest_vlan"],
        "urlRedirectWalledGardenEnabled": False,
    }

    payload_radius = {
        "name": meraki.params["name"],
        "radiusServers": meraki.params["radius_servers"],
        "radiusTestingEnabled": meraki.params["radius_testing"],
        "radiusGroupAttribute": convert_radius_attribute_group_policy_name(
            meraki.params["radius_attribute_group_policy_name"]
        ),
        "radius": {
            "criticalAuth": {
                "dataVlanId": convert_vlan_id(meraki.params["data_vlan_id"]),
                "voiceVlanId": convert_vlan_id(meraki.params["voice_vlan_id"]),
                "suspendPortBounce": meraki.params["suspend_port_bounce"],
            },
            "failedAuthVlanId": None,
            "reAuthenticationInterval": None,
        },
        "radiusCoaSupportEnabled": meraki.params["radius_coa_enabled"],
        "hostMode": meraki.params["host_mode"],
        "accessPolicyType": meraki.params["access_policy_type"],
        "guestVlanId": meraki.params["guest_vlan"],
        "voiceVlanClients": meraki.params["voice_vlan_clients"],
        "urlRedirectWalledGardenEnabled": False,
        "radiusAccountingEnabled": meraki.params["radius_accounting_enabled"],
        "radiusAccountingServers": meraki.params["radius_accounting_servers"],
        "systems_management_enrollment": meraki.params[
            "systems_management_enrollment"
        ],
    }

    if meraki.params["state"] == "query":
        if meraki.params["number"]:
            path = meraki.construct_path(
                "get_one",
                net_id=net_id,
                custom={
                    "number": meraki.params["number"],
                },
            )
            response = meraki.request(path, method="GET")
            meraki.result["data"] = response
        else:
            path = meraki.construct_path("get_all", net_id=net_id)
            response = meraki.request(path, method="GET")
            meraki.result["data"] = response
    elif meraki.params["state"] == "present":

        query_path_all = meraki.construct_path(
            "get_all",
            net_id=net_id,
        )

        original_all = meraki.request(query_path_all, method="GET")

        for i in original_all:
            if i.get("name") == meraki.params["name"]:
                meraki.params["number"] = i.get("accessPolicyNumber")

        if meraki.params["number"] is None:
            path = meraki.construct_path(
                "create",
                net_id=net_id,
            )
            if meraki.params["auth_method"] == "Meraki authentication":
                response = meraki.request(
                    path, method="POST", payload=json.dumps(payload_auth)
                )
                meraki.result["changed"] = True
                meraki.result["data"] = response
            elif meraki.params["auth_method"] == "my RADIUS server":
                response = meraki.request(
                    path, method="POST", payload=json.dumps(payload_radius)
                )
                meraki.result["changed"] = True
                meraki.result["data"] = response
        else:
            query_path = meraki.construct_path(
                "get_one",
                net_id=net_id,
                custom={
                    "number": meraki.params["number"],
                },
            )

            update_path = meraki.construct_path(
                "update",
                net_id=net_id,
                custom={
                    "number": meraki.params["number"],
                },
            )

            proposed = ""

            if meraki.params["auth_method"] == "Meraki authentication":
                proposed = payload_auth.copy()
            elif meraki.params["auth_method"] == "my RADIUS server":
                proposed = payload_radius.copy()

            original = meraki.request(query_path, method="GET")

            ignored_parameters = [
                "accessPolicyNumber",
                "secret",
                "systems_management_enrollment",
            ]

            if meraki.params["radius_accounting_enabled"]:
                proposed.update(
                    {
                        "radiusAccountingServers": meraki.params[
                            "radius_accounting_servers"
                        ],
                    }
                )
            else:
                proposed.update(
                    {
                        "radiusAccountingServers": [],
                    }
                )

            if meraki.params["radius_servers"]:
                proposed.update(
                    {
                        "radiusServers": meraki.params["radius_servers"],
                    }
                )
            else:
                proposed.update(
                    {
                        "radiusServers": [],
                    }
                )

            if meraki.is_update_required(
                original,
                proposed,
                optional_ignore=ignored_parameters,
            ):

                if meraki.check_mode is True:
                    original.update(proposed)
                    meraki.result["data"] = original
                    meraki.result["changed"] = True
                    meraki.exit_json(**meraki.result)

                response = meraki.request(
                    update_path, method="PUT", payload=json.dumps(proposed)
                )
                meraki.result["changed"] = True
                meraki.result["data"] = response
            else:
                meraki.result["data"] = original

    elif meraki.params["state"] == "absent":
        path = meraki.construct_path(
            "update",
            net_id=net_id,
            custom={
                "number": meraki.params["number"],
            },
        )

        response = meraki.request(path, method="DELETE")
        meraki.result["changed"] = True
        meraki.result["data"] = response

    meraki.exit_json(**meraki.result)


if __name__ == "__main__":
    main()
