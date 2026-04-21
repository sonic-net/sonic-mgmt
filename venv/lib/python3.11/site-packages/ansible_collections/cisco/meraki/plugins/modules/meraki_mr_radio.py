#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Tyler Christiansen (@supertylerc) <code@tylerc.me>
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
  - Tyler Christiansen (@supertylerc)
deprecated:
  alternative: cisco.meraki.devices_wireless_radio_settings
  removed_in: 3.0.0
  why: Updated modules released with increased functionality
description:
  - Allows for configuration of radio settings in Meraki MR wireless networks.
extends_documentation_fragment: cisco.meraki.meraki
module: meraki_mr_radio
options:
  five_ghz_settings:
    default: {}
    description:
      - Manual radio settings for 5 GHz.
    suboptions:
      channel:
        choices:
          - 36
          - 40
          - 44
          - 48
          - 52
          - 56
          - 60
          - 64
          - 100
          - 104
          - 108
          - 112
          - 116
          - 120
          - 124
          - 128
          - 132
          - 136
          - 140
          - 144
          - 149
          - 153
          - 157
          - 161
          - 165
        description:
          - Sets a manual channel for 5 GHz.
        type: int
      channel_width:
        choices:
          - auto
          - '20'
          - '40'
          - '80'
        description:
          - Sets a manual channel for 5 GHz.
          - Can be '0', '20', '40', or '80' or null for using auto channel width.
        type: str
      target_power:
        description:
          - Set a manual target power for 5 GHz.
          - Can be between '8' or '30' or null for using auto power range.
        type: int
    type: dict
  net_id:
    description:
      - ID of a network.
    type: str
  net_name:
    aliases:
      - network
    description:
      - Name of a network.
    type: str
  rf_profile_id:
    description:
      - The ID of an RF profile to assign to the device.
      - If the value of this parameter is null, the appropriate basic RF profile (indoor
        or outdoor) will be assigned to the device.
      - Assigning an RF profile will clear ALL manually configured overrides on the
        device (channel width, channel, power).
    type: str
  rf_profile_name:
    description:
      - The name of an RF profile to assign to the device.
      - Similar to ``rf_profile_id``, but requires ``net_id`` (preferred) or ``net_name``.
    type: str
  serial:
    description:
      - Serial number of a device to query.
    type: str
  state:
    choices:
      - present
      - query
    default: present
    description:
      - Query or edit radio settings on a device.
    type: str
  two_four_ghz_settings:
    default: {}
    description:
      - Manual radio settings for 2.4 GHz.
    suboptions:
      channel:
        choices:
          - 1
          - 2
          - 3
          - 4
          - 5
          - 6
          - 7
          - 8
          - 9
          - 10
          - 11
          - 12
          - 13
          - 14
        description:
          - Sets a manual channel for 2.4 GHz.
          - Can be '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12',
            '13' or '14' or null for using auto channel.
        type: int
      target_power:
        description:
          - Set a manual target power for 2.4 GHz.
          - Can be between '5' or '30' or null for using auto power range.
        type: int
    type: dict
short_description: Manage device radio settings for Meraki wireless networks
"""

EXAMPLES = r"""
- name: Query a device's radio configuration
  meraki_mr_radio:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    serial: YourSerialNumber
    state: query
  delegate_to: localhost
- name: Configure a device's radios
  meraki_mr_radio:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    serial: YourSerialNumber
    state: present
    five_ghz_settings:
      channel: 56
      channel_width: 20
      target_power: 10
    two_four_ghz_settings:
      channel: 6
      target_power: 12
    rf_profile_name: Test Profile
  delegate_to: localhost
"""

RETURN = r"""
data:
  description: RF settings configured on a specific device.
  returned: success
  type: complex
  contains:
    serial:
      description:
      - Serial number of the device that was configured.
      type: str
      returned: success
      sample: xyz
    rf_profile_id:
      description:
      - The ID of an RF profile assigned to the device.
      - Null indicates the appropriate basic RF profile (indoor or outdoor) is assigned to the device.
      type: str
      returned: success
      sample: null
    five_ghz_settings:
      description:
      - Configured manual radio settings for 5 GHz.
      type: dict
      returned: success
      contains:
        target_power:
          description:
          - Configured manual target power for 5 GHz.
          - Null indicates auto power.
          type: int
          sample: 25
        channel_width:
          description:
          - Configured manual channel for 5 GHz.
          - Null indicates auto channel width.
          type: str
          sample: 40
        channel:
          description:
          - Configured manual channel for 5 GHz.
          - Null indicates auto channel.
          type: str
          sample: 56
    two_four_ghz_settings:
      description:
      - Configured manual radio settings for 2.4 GHz.
      type: dict
      returned: success
      contains:
        target_power:
          description:
          - Configured manual target power for 2.4 GHz.
          - Null indicates auto power.
          type: int
          sample: 15
        channel:
          description:
          - Configured manual channel for 2.4 GHz.
          - Null indicates auto channel.
          type: str
          sample: 11
"""

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import (
    MerakiModule,
    meraki_argument_spec,
)
from re import sub


def convert_to_camel_case(string):
    """Convert "snake case" to "camel case"."""
    string = sub(r"(_|-)+", " ", string).title().replace(" ", "")
    return string[0].lower() + string[1:]


def _construct_payload(params):
    """Recursively convert key names.

    This function recursively updates all dict key names from the
    Ansible/Python-style "snake case" to the format the Meraki API expects
    ("camel case").
    """
    payload = {}
    for k, v in params.items():
        if isinstance(v, dict):
            v = _construct_payload(v)
        payload[convert_to_camel_case(k)] = v
    return payload


def construct_payload(meraki):
    """Construct API payload dict.

    This function uses a ``valid_params`` variable to filter out keys from
    ``meraki.params`` that aren't relevant to the Meraki API call.
    """
    params = {}
    valid_params = [
        "serial",
        "rf_profile_id",
        "five_ghz_settings",
        "two_four_ghz_settings",
    ]
    for k, v in meraki.params.items():
        if k not in valid_params:
            continue
        params[k] = v
    return _construct_payload(params)


# Ansible spec for the 'five_ghz_settings' param, based on Meraki API.
FIVE_GHZ_SETTINGS_SPEC = {
    "options": {
        "target_power": {"type": "int"},
        "channel_width": {"type": "str", "choices": ["auto", "20", "40", "80"]},
        "channel": {
            "type": "int",
            "choices": [
                36,
                40,
                44,
                48,
                52,
                56,
                60,
                64,
                100,
                104,
                108,
                112,
                116,
                120,
                124,
                128,
                132,
                136,
                140,
                144,
                149,
                153,
                157,
                161,
                165,
            ],
        },
    },
    "default": {},
}

# Ansible spec for the 'two_four_ghz_settings' param, based on Meraki API.
TWO_FOUR_GHZ_SETTINGS_SPEC = {
    "options": {
        "target_power": {"type": "int"},
        "channel": {
            "type": "int",
            "choices": list(range(1, 15)),
        },
    },
    "default": {},
}


def get_org_id(meraki):
    """Get the Organization ID based on the Organization Name."""
    org_id = meraki.params["org_id"]
    if org_id is None:
        org_id = meraki.get_org_id(meraki.params["org_name"])
    return org_id


def get_net_id(meraki):
    """Get the Network ID based on a Network Name."""
    net_id = meraki.params["net_id"]
    if net_id is None:
        org_id = get_org_id(meraki)
        nets = meraki.get_nets(org_id=org_id)
        net_id = meraki.get_net_id(org_id, meraki.params["net_name"], data=nets)
    return net_id


def get_rf_profile_id(meraki):
    """Get the RF Profile ID for a given RF Profile Name."""
    profile_id = meraki.params["rf_profile_id"]
    profile_name = meraki.params["rf_profile_name"]
    if profile_id is None and profile_name is not None:
        net_id = get_net_id(meraki)
        path = meraki.construct_path("get_all", "mr_rf_profile", net_id=net_id)
        profiles = meraki.request(path, method="GET")
        profile_id = next(
            (
                profile["id"]
                for profile in profiles
                if profile["name"] == meraki.params["rf_profile_name"]
            ),
            None,
        )
    return profile_id


def meraki_get_radio_settings(meraki):
    """Query the Meraki API for the current radio settings."""
    path = meraki.construct_path("get_one", custom={"serial": meraki.params["serial"]})
    return meraki.request(path, method="GET")


def _meraki_run_query(meraki):
    """Get the radio settings on the specified device."""
    meraki.result["data"] = meraki_get_radio_settings(meraki)
    meraki.exit_json(**meraki.result)


def _meraki_run_present(meraki):
    """Update / check radio settings for a specified device."""
    original = meraki_get_radio_settings(meraki)
    meraki.result["data"] = original
    meraki.params["rf_profile_id"] = get_rf_profile_id(meraki)
    payload = construct_payload(meraki)
    if meraki.is_update_required(original, payload) is True:
        if meraki.check_mode is True:
            meraki.result["data"] = payload
            meraki.result["changed"] = True
            meraki.result["original"] = original
        else:
            path = meraki.construct_path(
                "update", custom={"serial": meraki.params["serial"]}
            )
            response = meraki.request(path, method="PUT", payload=json.dumps(payload))
            meraki.result["data"] = response
            meraki.result["changed"] = True
    meraki.exit_json(**meraki.result)


def _meraki_run_func_lookup(state):
    """Return the function that `meraki_run` will use based on `state`."""
    return {
        "query": _meraki_run_query,
        "present": _meraki_run_present,
    }[state]


def meraki_run(meraki):
    """Perform API calls and generate responses based on the 'state' param."""
    meraki_run_func = _meraki_run_func_lookup(meraki.params["state"])
    meraki_run_func(meraki)


def update_url_catalog(meraki):
    """Update the URL catalog available to the helper."""
    query_urls = {"mr_radio": "/devices/{serial}/wireless/radio/settings"}
    update_urls = {"mr_radio": "/devices/{serial}/wireless/radio/settings"}
    query_all_urls = {"mr_rf_profile": "/networks/{net_id}/wireless/rfProfiles"}

    meraki.url_catalog["get_one"].update(query_urls)
    meraki.url_catalog["update"] = update_urls
    meraki.url_catalog["get_all"].update(query_all_urls)


def validate_params(params):
    """Validate parameters passed to this Ansible module.

    When ``rf_profile_name`` is passed, we need to lookup the ID as that's what
    the API expects.  To look up the RF Profile ID, we need the network ID,
    which might be derived based on the network name, in which case we need the
    org ID or org name to complete the process.
    """
    valid = True
    msg = None

    if (
        params["rf_profile_name"] is not None
        and params["rf_profile_id"] is None
        and params["net_id"] is None
    ):
        if params["net_name"] is None:
            valid = False
            msg = "When specifying 'rf_profile_name', either 'net_id' (preferred) or 'net_name' is required."
        elif params["org_id"] is None and params["org_name"] is None:
            valid = False
            msg = "When specifying 'rf_profile_name' and omitting 'net_id', either 'org_id' (preferred) or 'org_name' is required."
    return (valid, msg)


def main():
    argument_spec = meraki_argument_spec()
    argument_spec.update(
        state=dict(type="str", choices=["present", "query"], default="present"),
        org_name=dict(type="str", aliases=["organization"]),
        org_id=dict(type="str"),
        net_name=dict(type="str", aliases=["network"]),
        net_id=dict(type="str"),
        serial=dict(type="str"),
        rf_profile_name=(dict(type="str")),
        rf_profile_id=dict(type="str"),
        five_ghz_settings=dict(
            type="dict",
            options=FIVE_GHZ_SETTINGS_SPEC["options"],
            default=FIVE_GHZ_SETTINGS_SPEC["default"],
        ),
        two_four_ghz_settings=dict(
            type="dict",
            options=TWO_FOUR_GHZ_SETTINGS_SPEC["options"],
            default=TWO_FOUR_GHZ_SETTINGS_SPEC["default"],
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    meraki = MerakiModule(module, function="mr_radio")
    meraki.params["follow_redirects"] = "all"
    valid_params, msg = validate_params(meraki.params)
    if not valid_params:
        meraki.fail_json(msg=msg)

    update_url_catalog(meraki)
    meraki_run(meraki)


if __name__ == "__main__":
    main()
