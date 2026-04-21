#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
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
  alternative: cisco.meraki.networks_syslog_servers
  removed_in: 3.0.0
  why: Updated modules released with increased functionality
description:
  - Allows for creation and management of Syslog servers within Meraki.
extends_documentation_fragment: cisco.meraki.meraki
module: meraki_syslog
notes:
  - Changes to existing syslog servers replaces existing configuration. If you need
    to add to an existing configuration set state to query to gather the existing
    configuration and then modify or add.
options:
  auth_key:
    description:
      - Authentication key provided by the dashboard. Required if environmental variable
        MERAKI_KEY is not set.
    type: str
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
  servers:
    description:
      - List of syslog server settings
    elements: dict
    suboptions:
      host:
        description:
          - IP address or hostname of Syslog server.
        type: str
      port:
        default: '514'
        description:
          - Port number Syslog server is listening on.
        type: int
      roles:
        description:
          - List of applicable Syslog server roles.
          - Choices can be one of Wireless Event log, Appliance event log, Switch
            event log, Air Marshal events, Flows, URLs, IDS alerts, Security events
        elements: str
        type: list
    type: list
  state:
    choices:
      - present
      - query
    default: present
    description:
      - Query or edit syslog servers
      - To delete a syslog server, do not include server in list of servers
    type: str
short_description: Manage syslog server settings in the Meraki cloud.
"""

EXAMPLES = r"""
- name: Query syslog configurations on network named MyNet in the YourOrg organization
  meraki_syslog:
    auth_key: abc12345
    state: query
    org_name: YourOrg
    net_name: MyNet
  delegate_to: localhost
- name: Add single syslog server with Appliance event log role
  meraki_syslog:
    auth_key: abc12345
    state: present
    org_name: YourOrg
    net_name: MyNet
    servers:
      - host: 192.0.1.2
        port: 514
        roles:
          - Appliance event log
  delegate_to: localhost
- name: Add multiple syslog servers
  meraki_syslog:
    auth_key: abc12345
    state: present
    org_name: YourOrg
    net_name: MyNet
    servers:
      - host: 192.0.1.2
        port: 514
        roles:
          - Appliance event log
      - host: 192.0.1.3
        port: 514
        roles:
          - Appliance event log
          - Flows
  delegate_to: localhost
"""

RETURN = r"""
data:
    description: Information about the created or manipulated object.
    returned: info
    type: complex
    contains:
      servers:
        description: List of syslog servers.
        returned: info
        type: complex
        contains:
          host:
            description: Hostname or IP address of syslog server.
            returned: success
            type: str
            sample: 192.0.1.1
          port:
            description: Port number for syslog communication.
            returned: success
            type: str
            sample: 443
          roles:
            description: List of roles assigned to syslog server.
            returned: success
            type: list
            sample: "Wireless event log, URLs"
"""

from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import (
    MerakiModule,
    meraki_argument_spec,
)


def sort_roles(syslog_servers):
    """Accept a full payload and sort roles"""
    # sorted_servers = list()
    for i, server in enumerate(syslog_servers):
        syslog_servers["servers"][i]["roles"] = sorted(
            syslog_servers["servers"][i]["roles"]
        )
    # return sorted_servers


def validate_role_choices(meraki, servers):
    choices = [
        "Wireless event log",
        "Appliance event log",
        "Switch event log",
        "Air Marshal events",
        "Flows",
        "URLs",
        "IDS alerts",
        "Security events",
    ]

    # Change all choices to lowercase for comparison
    for i in range(len(choices)):
        choices[i] = choices[i].lower()
    for server in range(len(servers)):
        for role in servers[server]["roles"]:
            if role.lower() not in choices:
                meraki.fail_json(
                    msg="Invalid role found in {0}.".format(servers[server]["host"])
                )


def normalize_roles(meraki, servers):
    if len(servers["servers"]) > 0:
        for server in range(len(servers)):
            for role in range(len(servers["servers"][server]["roles"])):
                servers["servers"][server]["roles"][role] = servers["servers"][server][
                    "roles"
                ][role].lower()
    return servers


def main():

    # define the available arguments/parameters that a user can pass to
    # the module

    server_arg_spec = dict(
        host=dict(type="str"),
        port=dict(type="int", default="514"),
        roles=dict(
            type="list",
            elements="str",
        ),
    )

    argument_spec = meraki_argument_spec()
    argument_spec.update(
        net_id=dict(type="str"),
        servers=dict(type="list", elements="dict", options=server_arg_spec),
        state=dict(type="str", choices=["present", "query"], default="present"),
        net_name=dict(type="str", aliases=["name", "network"]),
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    meraki = MerakiModule(module, function="syslog")
    module.params["follow_redirects"] = "all"
    payload = None

    syslog_urls = {"syslog": "/networks/{net_id}/syslogServers"}
    meraki.url_catalog["query_update"] = syslog_urls

    if not meraki.params["org_name"] and not meraki.params["org_id"]:
        meraki.fail_json(msg="org_name or org_id parameters are required")
    if meraki.params["state"] != "query":
        if not meraki.params["net_name"] and not meraki.params["net_id"]:
            meraki.fail_json(
                msg="net_name or net_id is required for present or absent states"
            )
    if meraki.params["net_name"] and meraki.params["net_id"]:
        meraki.fail_json(msg="net_name and net_id are mutually exclusive")

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)

    org_id = meraki.params["org_id"]
    if not org_id:
        org_id = meraki.get_org_id(meraki.params["org_name"])
    net_id = meraki.params["net_id"]
    if net_id is None:
        nets = meraki.get_nets(org_id=org_id)
        net_id = meraki.get_net_id(net_name=meraki.params["net_name"], data=nets)

    if meraki.params["state"] == "query":
        path = meraki.construct_path("query_update", net_id=net_id)
        r = meraki.request(path, method="GET")
        if meraki.status == 200:
            meraki.result["data"] = r
    elif meraki.params["state"] == "present":
        # Validate roles
        validate_role_choices(meraki, meraki.params["servers"])

        # Construct payload
        payload = dict()
        payload["servers"] = meraki.params["servers"]

        # Convert port numbers to string for idempotency checks
        for server in payload["servers"]:
            if server["port"]:
                server["port"] = str(server["port"])
        path = meraki.construct_path("query_update", net_id=net_id)
        r = meraki.request(path, method="GET")
        if meraki.status == 200:
            original = r

        # Roles must be sorted since out of order responses may break idempotency check
        # Need to check to make sure servers are actually defined
        if original is not None:
            if len(original["servers"]) > 0:
                sort_roles(original)
        if payload is not None:
            if len(payload["servers"]) > 0:
                sort_roles(payload)

        # Sanitize roles for comparison
        sanitized_original = normalize_roles(meraki, deepcopy(original))
        sanitized_payload = normalize_roles(meraki, deepcopy(payload))

        if meraki.is_update_required(sanitized_original, sanitized_payload):
            if meraki.module.check_mode is True:
                meraki.generate_diff(original, payload)
                original.update(payload)
                meraki.result["data"] = original
                meraki.result["changed"] = True
                meraki.exit_json(**meraki.result)
            path = meraki.construct_path("query_update", net_id=net_id)
            r = meraki.request(path, method="PUT", payload=json.dumps(payload))
            if meraki.status == 200:
                meraki.generate_diff(original, r)
                meraki.result["data"] = r
                meraki.result["changed"] = True
        else:
            if meraki.module.check_mode is True:
                meraki.result["data"] = original
                meraki.exit_json(**meraki.result)
            meraki.result["data"] = original

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == "__main__":
    main()
