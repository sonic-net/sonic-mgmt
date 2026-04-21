#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023 Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
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
  alternative: cisco.meraki.networks_settings
  removed_in: 3.0.0
  why: Updated modules released with increased functionality
description:
  - Allows for management of settings of networks within Meraki.
extends_documentation_fragment: cisco.meraki.meraki
module: meraki_network_settings
options:
  local_status_page:
    description:
      - Configuration stanza of the local status page.
    suboptions:
      authentication:
        description:
          - Local status page authentication settings.
        suboptions:
          enabled:
            description:
              - Set whether local status page authentication is enabled.
            type: bool
          password:
            description:
              - Set password on local status page.
            type: str
        type: dict
    type: dict
  local_status_page_enabled:
    description: '- Enables the local device status pages (U[my.meraki.com](my.meraki.com),
      U[ap.meraki.com](ap.meraki.com), U[switch.meraki.com](switch.meraki.com), U[wired.meraki.com](wired.meraki.com)).
      - Only can be specified on its own or with C(remote_status_page_enabled).

      '
    type: bool
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
  remote_status_page_enabled:
    description:
      - Enables access to the device status page (U(http://device LAN IP)).
      - Can only be set if C(local_status_page_enabled:) is set to C(yes).
      - Only can be specified on its own or with C(local_status_page_enabled).
    type: bool
  secure_port:
    description:
      - Configuration of SecureConnect options applied to the network.
    suboptions:
      enabled:
        description:
          - Set whether SecureConnect is enabled on the network.
        type: bool
    type: dict
  state:
    choices:
      - present
      - query
    default: query
    description:
      - Create or modify an organization.
    type: str
short_description: Manage the settings of networks in the Meraki cloud
"""

EXAMPLES = r"""
- name: Get network settings
  cisco.meraki.meraki_network_settings:
    auth_key: '{{ auth_key }}'
    state: query
    org_name: '{{ test_org_name }}'
    net_name: NetworkSettingsTestNet
  delegate_to: localhost
- name: Update network settings
  cisco.meraki.meraki_network_settings:
    auth_key: '{{ auth_key }}'
    state: present
    org_name: '{{ test_org_name }}'
    net_name: NetworkSettingsTestNet
    local_status_page_enabled: false
  delegate_to: localhost
- name: Enable password on local page
  cisco.meraki.meraki_network_settings:
    auth_key: '{{ auth_key }}'
    state: present
    org_name: '{{ test_org_name }}'
    net_name: NetworkSettingsTestNet
    local_status_page_enabled: true
    local_status_page:
      authentication:
        enabled: true
        password: abc123
  delegate_to: localhost
"""

RETURN = r"""
data:
    description: Information about the created or manipulated object.
    returned: info
    type: complex
    contains:
      local_status_page_enabled:
        description: States whether U(my.meraki.com) and other device portals should be enabled.
        returned: success
        type: bool
        sample: true
      remote_status_page_enabled:
        description: Enables access to the device status page.
        returned: success
        type: bool
        sample: true
      expire_data_older_than:
        description: The number of days, weeks, or months in Epoch time to expire the data before
        returned: success
        type: int
        sample: 1234
      fips:
        description: A hash of FIPS options applied to the Network.
        returned: success
        type: complex
        contains:
          enabled:
            description: Enables/disables FIPS on the network.
            returned: success
            type: bool
            sample: true
      local_status_page:
        description: A hash of Local Status Page(s) authentication options applied to the Network.
        returned: success
        type: complex
        contains:
          authentication:
            description: A hash of Local Status Pages' authentication options applied to the Network.
            type: complex
            contains:
              username:
                description: The username used for Local Status Pages.
                type: str
                returned: success
                sample: admin
              enabled:
                description: Enables/Disables the authenticaiton on Local Status Pages.
                type: bool
                returned: success
            sample: true
      secure_port:
        description: A hash of SecureConnect options applied to the Network.
        type: complex
        contains:
          enabled:
            description: Enables/disables SecureConnect on the network.
            type: bool
            returned: success
            sample: true
      named_vlans:
        description: A hash of Named VLANs options applied to the Network.
        type: complex
        contains:
          enabled:
            description: Enables/disables Named VLANs on the network.
            type: bool
            returned: success
            sample: true
"""

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import (
    MerakiModule,
    meraki_argument_spec,
)


def is_net_valid(data, net_name=None, net_id=None):
    if net_name is None and net_id is None:
        return False
    for n in data:
        if net_name:
            if n["name"] == net_name:
                return True
        elif net_id:
            if n["id"] == net_id:
                return True
    return False


def get_network_settings(meraki, net_id):
    path = meraki.construct_path("get_settings", net_id=net_id)
    response = meraki.request(path, method="GET")
    return response


def construct_payload(params):
    payload = dict()
    if params["local_status_page_enabled"] is not None:
        payload["localStatusPageEnabled"] = params["local_status_page_enabled"]
    if params["remote_status_page_enabled"] is not None:
        payload["remoteStatusPageEnabled"] = params["remote_status_page_enabled"]
    if params["local_status_page"] is not None:
        payload["localStatusPage"] = dict()
        if params["local_status_page"]["authentication"] is not None:
            payload["localStatusPage"]["authentication"] = {}
            if params["local_status_page"]["authentication"]["enabled"] is not None:
                payload["localStatusPage"]["authentication"]["enabled"] = params["local_status_page"]["authentication"]["enabled"]
            if params["local_status_page"]["authentication"]["password"] is not None:
                payload["localStatusPage"]["authentication"]["password"] = params["local_status_page"]["authentication"]["password"]
    if params["secure_port"] is not None:
        payload["securePort"] = dict()
        if params["secure_port"]["enabled"] is not None:
            payload["securePort"]["enabled"] = params["secure_port"]["enabled"]
    return payload


def main():

    # define the available arguments/parameters that a user can pass to
    # the module

    auth_args = dict(
        enabled=dict(type="bool"),
        password=dict(type="str", no_log=True),
    )

    local_status_page_args = dict(
        authentication=dict(type="dict", default=None, options=auth_args),
    )

    secure_port_args = dict(
        enabled=dict(type="bool"),
    )

    argument_spec = meraki_argument_spec()
    argument_spec.update(
        state=dict(type="str", choices=["query", "present"], default="query"),
        net_name=dict(type="str", aliases=["name", "network"]),
        net_id=dict(type="str"),
        local_status_page_enabled=dict(type="bool"),
        remote_status_page_enabled=dict(type="bool"),
        local_status_page=dict(type="dict", default=None, options=local_status_page_args),
        secure_port=dict(type="dict", default=None, options=secure_port_args)
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    meraki = MerakiModule(module, function="network")
    module.params["follow_redirects"] = "all"
    payload = None

    update_settings_urls = {"network": "/networks/{net_id}/settings"}
    get_settings_urls = {"network": "/networks/{net_id}/settings"}
    meraki.url_catalog["update_settings"] = update_settings_urls
    meraki.url_catalog["get_settings"] = get_settings_urls

    if not meraki.params["org_name"] and not meraki.params["org_id"]:
        meraki.fail_json(msg="org_name or org_id parameters are required")
    if meraki.params["state"] != "query":
        if not meraki.params["net_name"] and not meraki.params["net_id"]:
            meraki.fail_json(
                msg="net_name or net_id is required for present or absent states"
            )
    if meraki.params["net_name"] and meraki.params["net_id"]:
        meraki.fail_json(msg="net_name and net_id are mutually exclusive")
    if (
        meraki.params["local_status_page_enabled"] is False
        and meraki.params["remote_status_page_enabled"] is True
    ):
        meraki.fail_json(
            msg="local_status_page_enabled must be true when setting remote_status_page_enabled"
        )

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)

    org_id = meraki.params["org_id"]
    net_id = meraki.params["net_id"]
    if not org_id:
        org_id = meraki.get_org_id(meraki.params["org_name"])
    if net_id is None:
        nets = meraki.get_nets(org_id=org_id)
        net_id = meraki.get_net_id(org_id, meraki.params["net_name"], data=nets)

    if meraki.params["state"] == "query":
        path = meraki.construct_path("get_settings", net_id=net_id)
        meraki.result["data"] = meraki.request(path, method="GET")
        meraki.exit_json(**meraki.result)
    elif meraki.params["state"] == "present":
        path = meraki.construct_path("get_settings", net_id=net_id)
        current = meraki.request(path, method="GET")
        payload = construct_payload(meraki.params)
        if meraki.is_update_required(current, payload, optional_ignore=["password"]):
            if meraki.check_mode is True:
                try:
                    del payload["local_status_page"]["authentication"]["password"]
                except KeyError:
                    pass
                meraki.result["data"] = payload
                meraki.result["changed"] = True
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path("update_settings", net_id=net_id)
            response = meraki.request(path, method="PUT", payload=json.dumps(payload))
            if meraki.status == 200:
                meraki.result["changed"] = True
                meraki.result["data"] = response
                meraki.exit_json(**meraki.result)
        meraki.result["data"] = current
    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == "__main__":
    main()
