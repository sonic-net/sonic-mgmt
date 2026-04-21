#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022 Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
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
  - Kevin Breit (@kbreit)
deprecated:
  alternative: cisco.meraki.networks_appliance_vlans_settings
  removed_in: 3.0.0
  why: Updated modules released with increased functionality
description:
  - Edits VLAN enabled status on a network within Meraki.
extends_documentation_fragment: cisco.meraki.meraki
module: meraki_mx_network_vlan_settings
options:
  net_id:
    description:
      - ID number of a network.
    type: str
  net_name:
    aliases:
      - name
      - network
    description:
      - Name of a network.
    type: str
  state:
    choices:
      - present
      - query
    description:
      - Create or modify an alert.
    type: str
  vlans_enabled:
    description:
      - Whether VLANs are enabled on the network.
    type: bool
short_description: Manage VLAN settings for Meraki Networks
"""

EXAMPLES = r"""
- name: Update settings
  meraki_mx_network_vlan_settings:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: present
    vlans_enabled: true
"""

RETURN = r"""
data:
    description: Information about the created or manipulated object.
    returned: info
    type: complex
    contains:
        vlans_enabled:
            description: Whether VLANs are enabled for this network.
            returned: success
            type: bool
"""

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import (
    MerakiModule,
    meraki_argument_spec,
)


def construct_payload(meraki):
    payload = {"vlansEnabled": meraki.params["vlans_enabled"]}
    return payload


def main():

    # define the available arguments/parameters that a user can pass to
    # the module

    argument_spec = meraki_argument_spec()
    argument_spec.update(
        net_id=dict(type="str"),
        net_name=dict(type="str", aliases=["name", "network"]),
        state=dict(type="str", choices=["query", "present"]),
        vlans_enabled=dict(type="bool"),
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    meraki = MerakiModule(module, function="network_vlan_settings")
    module.params["follow_redirects"] = "all"

    query_urls = {
        "network_vlan_settings": "/networks/{net_id}/appliance/vlans/settings"
    }
    update_urls = {
        "network_vlan_settings": "/networks/{net_id}/appliance/vlans/settings"
    }
    meraki.url_catalog["get_all"].update(query_urls)
    meraki.url_catalog["update"] = update_urls

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)

    org_id = meraki.params["org_id"]
    if org_id is None:
        org_id = meraki.get_org_id(meraki.params["org_name"])
    net_id = meraki.params["net_id"]
    if net_id is None:
        nets = meraki.get_nets(org_id=org_id)
        net_id = meraki.get_net_id(net_name=meraki.params["net_name"], data=nets)

    if meraki.params["state"] == "query":
        path = meraki.construct_path("get_all", net_id=net_id)
        response = meraki.request(path, method="GET")
        if meraki.status == 200:
            meraki.result["data"] = response
        meraki.exit_json(**meraki.result)
    elif meraki.params["state"] == "present":
        path = meraki.construct_path("get_all", net_id=net_id)
        original = meraki.request(path, method="GET")
        payload = construct_payload(meraki)
        if meraki.is_update_required(original, payload):
            if meraki.check_mode is True:
                meraki.generate_diff(original, payload)
                meraki.result["data"] = payload
                meraki.result["changed"] = True
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path("update", net_id=net_id)
            response = meraki.request(path, method="PUT", payload=json.dumps(payload))
            if meraki.status == 200:
                meraki.generate_diff(original, payload)
                meraki.result["data"] = response
                meraki.result["changed"] = True
                meraki.exit_json(**meraki.result)
        else:
            meraki.result["data"] = original
            meraki.exit_json(**meraki.result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == "__main__":
    main()
