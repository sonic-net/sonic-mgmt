#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, 2019 Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
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
  alternative: cisco.meraki.networks
  removed_in: 3.0.0
  why: Updated modules released with increased functionality
description:
  - Allows for creation, management, and visibility into networks within Meraki.
extends_documentation_fragment: cisco.meraki.meraki
module: meraki_network
options:
  copy_from_network_id:
    description:
      - New network inherits properties from this network ID.
      - Other provided parameters will override the copied configuration.
      - Type which must match this network's type exactly.
    type: str
  enable_vlans:
    description:
      - Boolean value specifying whether VLANs should be supported on a network.
      - Requires C(net_name) or C(net_id) to be specified.
    type: bool
  local_status_page_enabled:
    description: '- This no longer works and will likely be moved to a separate module.
      - Enables the local device status pages (U[my.meraki.com](my.meraki.com), U[ap.meraki.com](ap.meraki.com),
      U[switch.meraki.com](switch.meraki.com), U[wired.meraki.com](wired.meraki.com)).
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
      - This no longer works and will likely be moved to a separate module.
      - Enables access to the device status page (U(http://device LAN IP)).
      - Can only be set if C(local_status_page_enabled:) is set to C(yes).
      - Only can be specified on its own or with C(local_status_page_enabled).
    type: bool
  state:
    choices:
      - absent
      - present
      - query
    default: present
    description:
      - Create or modify an organization.
    type: str
  tags:
    description:
      - List of tags to assign to network.
      - C(tags) name conflicts with the tags parameter in Ansible. Indentation problems
        may cause unexpected behaviors.
      - Ansible 2.8 converts this to a list from a comma separated list.
    elements: str
    type: list
  timezone:
    description:
      - Timezone associated to network.
      - See U(https://en.wikipedia.org/wiki/List_of_tz_database_time_zones) for a
        list of valid timezones.
    type: str
  type:
    aliases:
      - net_type
    choices:
      - appliance
      - switch
      - wireless
      - sensor
      - systemsManager
      - camera
      - cellularGateway
    description:
      - Type of network device network manages.
      - Required when creating a network.
      - As of Ansible 2.8, C(combined) type is no longer accepted.
      - As of Ansible 2.8, changes to this parameter are no longer idempotent.
    elements: str
    type: list
short_description: Manage networks in the Meraki cloud
"""

EXAMPLES = r"""
- delegate_to: localhost
  block:
    - name: List all networks associated to the YourOrg organization
      meraki_network:
        auth_key: abc12345
        state: query
        org_name: YourOrg
    - name: Query network named MyNet in the YourOrg organization
      meraki_network:
        auth_key: abc12345
        state: query
        org_name: YourOrg
        net_name: MyNet
    - name: Create network named MyNet in the YourOrg organization
      meraki_network:
        auth_key: abc12345
        state: present
        org_name: YourOrg
        net_name: MyNet
        type: switch
        timezone: America/Chicago
        tags: production, chicago
    - name: Create combined network named MyNet in the YourOrg organization
      meraki_network:
        auth_key: abc12345
        state: present
        org_name: YourOrg
        net_name: MyNet
        type:
          - switch
          - appliance
        timezone: America/Chicago
        tags: production, chicago
    - name: Create new network based on an existing network
      meraki_network:
        auth_key: abc12345
        state: present
        org_name: YourOrg
        net_name: MyNet
        type:
          - switch
          - appliance
        copy_from_network_id: N_1234
    - name: Enable VLANs on a network
      meraki_network:
        auth_key: abc12345
        state: query
        org_name: YourOrg
        net_name: MyNet
        enable_vlans: true
    - name: Modify local status page enabled state
      meraki_network:
        auth_key: abc12345
        state: query
        org_name: YourOrg
        net_name: MyNet
        local_status_page_enabled: true
"""

RETURN = r"""
data:
    description: Information about the created or manipulated object.
    returned: info
    type: complex
    contains:
      id:
        description: Identification string of network.
        returned: success
        type: str
        sample: N_12345
      name:
        description: Written name of network.
        returned: success
        type: str
        sample: YourNet
      organization_id:
        description: Organization ID which owns the network.
        returned: success
        type: str
        sample: 0987654321
      tags:
        description: Space delimited tags assigned to network.
        returned: success
        type: list
        sample: ['production']
      time_zone:
        description: Timezone where network resides.
        returned: success
        type: str
        sample: America/Chicago
      type:
        description: Functional type of network.
        returned: success
        type: list
        sample: ['switch']
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


def main():

    # define the available arguments/parameters that a user can pass to
    # the module

    argument_spec = meraki_argument_spec()
    argument_spec.update(
        net_id=dict(type="str"),
        type=dict(
            type="list",
            elements="str",
            choices=[
                "wireless",
                "switch",
                "appliance",
                "sensor",
                "systemsManager",
                "camera",
                "cellularGateway",
            ],
            aliases=["net_type"],
        ),
        tags=dict(type="list", elements="str"),
        timezone=dict(type="str"),
        net_name=dict(type="str", aliases=["name", "network"]),
        state=dict(
            type="str", choices=["present", "query", "absent"], default="present"
        ),
        enable_vlans=dict(type="bool"),
        local_status_page_enabled=dict(type="bool"),
        remote_status_page_enabled=dict(type="bool"),
        copy_from_network_id=dict(type="str"),
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

    create_urls = {"network": "/organizations/{org_id}/networks"}
    update_urls = {"network": "/networks/{net_id}"}
    delete_urls = {"network": "/networks/{net_id}"}
    update_settings_urls = {"network": "/networks/{net_id}/settings"}
    get_settings_urls = {"network": "/networks/{net_id}/settings"}
    enable_vlans_urls = {"network": "/networks/{net_id}/appliance/vlans/settings"}
    get_vlan_status_urls = {"network": "/networks/{net_id}/appliance/vlans/settings"}
    meraki.url_catalog["create"] = create_urls
    meraki.url_catalog["update"] = update_urls
    meraki.url_catalog["update_settings"] = update_settings_urls
    meraki.url_catalog["get_settings"] = get_settings_urls
    meraki.url_catalog["delete"] = delete_urls
    meraki.url_catalog["enable_vlans"] = enable_vlans_urls
    meraki.url_catalog["status_vlans"] = get_vlan_status_urls

    if not meraki.params["org_name"] and not meraki.params["org_id"]:
        meraki.fail_json(msg="org_name or org_id parameters are required")
    if meraki.params["state"] != "query":
        if not meraki.params["net_name"] and not meraki.params["net_id"]:
            meraki.fail_json(
                msg="net_name or net_id is required for present or absent states"
            )
    if meraki.params["net_name"] and meraki.params["net_id"]:
        meraki.fail_json(msg="net_name and net_id are mutually exclusive")
    if not meraki.params["net_name"] and not meraki.params["net_id"]:
        if meraki.params["enable_vlans"]:
            meraki.fail_json(
                msg="The parameter 'enable_vlans' requires 'net_name' or 'net_id' to be specified"
            )
    if (
        meraki.params["local_status_page_enabled"] is False
        and meraki.params["remote_status_page_enabled"] is True
    ):
        meraki.fail_json(
            msg="local_status_page_enabled must be true when setting remote_status_page_enabled"
        )

    # Construct payload
    if meraki.params["state"] == "present":
        payload = dict()
        if meraki.params["net_name"]:
            payload["name"] = meraki.params["net_name"]
        if meraki.params["type"]:
            payload["productTypes"] = meraki.params["type"]
        if meraki.params["tags"]:
            payload["tags"] = meraki.params["tags"]
        if meraki.params["timezone"]:
            payload["timeZone"] = meraki.params["timezone"]
        if meraki.params["local_status_page_enabled"] is not None:
            payload["localStatusPageEnabled"] = meraki.params[
                "local_status_page_enabled"
            ]
        if meraki.params["remote_status_page_enabled"] is not None:
            payload["remoteStatusPageEnabled"] = meraki.params[
                "remote_status_page_enabled"
            ]
        if meraki.params["copy_from_network_id"] is not None:
            payload["copyFromNetworkId"] = meraki.params["copy_from_network_id"]

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)

    org_id = meraki.params["org_id"]
    if not org_id:
        org_id = meraki.get_org_id(meraki.params["org_name"])
    nets = meraki.get_nets(org_id=org_id)
    net_id = meraki.params["net_id"]
    net_exists = False
    if net_id is not None:
        if is_net_valid(nets, net_id=net_id) is False:
            meraki.fail_json(msg="Network specified by net_id does not exist.")
        net_exists = True
    elif meraki.params["net_name"]:
        if is_net_valid(nets, net_name=meraki.params["net_name"]) is True:
            net_id = meraki.get_net_id(net_name=meraki.params["net_name"], data=nets)
            net_exists = True

    if meraki.params["state"] == "query":
        if not meraki.params["net_name"] and not meraki.params["net_id"]:
            meraki.result["data"] = nets
        elif meraki.params["net_name"] or meraki.params["net_id"] is not None:
            if (
                meraki.params["local_status_page_enabled"] is not None
                or meraki.params["remote_status_page_enabled"] is not None
            ):
                meraki.result["data"] = get_network_settings(meraki, net_id)
                meraki.exit_json(**meraki.result)
            else:
                meraki.result["data"] = meraki.get_net(
                    meraki.params["org_name"], net_name=meraki.params["net_name"], data=nets, net_id=meraki.params["net_id"],
                )
                meraki.exit_json(**meraki.result)
    elif meraki.params["state"] == "present":
        if net_exists is False:  # Network needs to be created
            if "type" not in meraki.params or meraki.params["type"] is None:
                meraki.fail_json(
                    msg="type parameter is required when creating a network."
                )
            if meraki.check_mode is True:
                data = payload
                data["id"] = "N_12345"
                data["organization_id"] = org_id
                meraki.result["data"] = data
                meraki.result["changed"] = True
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path("create", org_id=org_id)
            r = meraki.request(path, method="POST", payload=json.dumps(payload))
            if meraki.status == 201:
                meraki.result["data"] = r
                meraki.result["changed"] = True
        else:  # Network exists, make changes
            if meraki.params["enable_vlans"] is not None:  # Modify VLANs configuration
                status_path = meraki.construct_path("status_vlans", net_id=net_id)
                status = meraki.request(status_path, method="GET")
                payload = {"vlansEnabled": meraki.params["enable_vlans"]}
                if meraki.is_update_required(status, payload):
                    if meraki.check_mode is True:
                        data = {
                            "vlansEnabled": meraki.params["enable_vlans"],
                            "network_id": net_id,
                        }
                        meraki.result["data"] = data
                        meraki.result["changed"] = True
                        meraki.exit_json(**meraki.result)
                    path = meraki.construct_path("enable_vlans", net_id=net_id)
                    r = meraki.request(path, method="PUT", payload=json.dumps(payload))
                    if meraki.status == 200:
                        meraki.result["data"] = r
                        meraki.result["changed"] = True
                        meraki.exit_json(**meraki.result)
                else:
                    meraki.result["data"] = status
                    meraki.exit_json(**meraki.result)
            elif (
                meraki.params["local_status_page_enabled"] is not None
                or meraki.params["remote_status_page_enabled"] is not None
            ):
                path = meraki.construct_path("get_settings", net_id=net_id)
                original = meraki.request(path, method="GET")
                payload = {}
                if meraki.params["local_status_page_enabled"] is not None:
                    payload["localStatusPageEnabled"] = meraki.params[
                        "local_status_page_enabled"
                    ]
                if meraki.params["remote_status_page_enabled"] is not None:
                    payload["remoteStatusPageEnabled"] = meraki.params[
                        "remote_status_page_enabled"
                    ]
                if meraki.is_update_required(original, payload):
                    if meraki.check_mode is True:
                        original.update(payload)
                        meraki.result["data"] = original
                        meraki.result["changed"] = True
                        meraki.exit_json(**meraki.result)
                    path = meraki.construct_path("update_settings", net_id=net_id)
                    response = meraki.request(
                        path, method="PUT", payload=json.dumps(payload)
                    )
                    meraki.result["data"] = response
                    meraki.result["changed"] = True
                    meraki.exit_json(**meraki.result)
                else:
                    meraki.result["data"] = original
                    meraki.exit_json(**meraki.result)
            net = meraki.get_net(meraki.params["org_name"], net_id=net_id, data=nets)
            if meraki.is_update_required(net, payload):
                if meraki.check_mode is True:
                    data = net
                    net.update(payload)
                    meraki.result["data"] = net
                    meraki.result["changed"] = True
                    meraki.exit_json(**meraki.result)
                path = meraki.construct_path("update", net_id=net_id)
                r = meraki.request(path, method="PUT", payload=json.dumps(payload))
                if meraki.status == 200:
                    meraki.result["data"] = r
                    meraki.result["changed"] = True
            else:
                meraki.result["data"] = net
    elif meraki.params["state"] == "absent":
        if is_net_valid(nets, net_id=net_id) is True:
            if meraki.check_mode is True:
                meraki.result["data"] = {}
                meraki.result["changed"] = True
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path("delete", net_id=net_id)
            r = meraki.request(path, method="DELETE")
            if meraki.status == 204:
                meraki.result["changed"] = True

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == "__main__":
    main()
