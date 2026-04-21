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
  alternative: cisco.meraki.networks_alerts_settings
  removed_in: 3.0.0
  why: Updated modules released with increased functionality
description:
  - Allows for creation, management, and visibility into alert settings within Meraki.
extends_documentation_fragment: cisco.meraki.meraki
module: meraki_alert
options:
  alerts:
    description:
      - Alert-specific configuration for each type.
    elements: dict
    suboptions:
      alert_destinations:
        description:
          - A hash of destinations for this specific alert.
        suboptions:
          all_admins:
            description:
              - If true, all network admins will receive emails.
            type: bool
          emails:
            description:
              - A list of emails that will recieve the alert(s).
            elements: str
            type: list
          http_server_ids:
            description:
              - A list of HTTP server IDs to send a Webhook to.
            elements: str
            type: list
          snmp:
            description:
              - If true, then an SNMP trap will be sent if there is an SNMP trap server
                configured for this network.
            type: bool
        type: dict
      alert_type:
        description:
          - The type of alert.
        type: str
      enabled:
        description:
          - A boolean depicting if the alert is turned on or off.
        type: bool
      filters:
        default: {}
        description:
          - A hash of specific configuration data for the alert. Only filters specific
            to the alert will be updated.
          - No validation checks occur against C(filters).
        type: raw
    type: list
  default_destinations:
    description:
      - Properties for destinations when alert specific destinations aren't specified.
    suboptions:
      all_admins:
        description:
          - If true, all network admins will receive emails.
        type: bool
      emails:
        description:
          - A list of emails that will recieve the alert(s).
        elements: str
        type: list
      http_server_ids:
        description:
          - A list of HTTP server IDs to send a Webhook to.
        elements: str
        type: list
      snmp:
        description:
          - If true, then an SNMP trap will be sent if there is an SNMP trap server
            configured for this network.
        type: bool
    type: dict
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
    default: present
    description:
      - Create or modify an alert.
    type: str
short_description: Manage alerts in the Meraki cloud
version_added: 2.1.0
"""

EXAMPLES = r"""
- name: Update settings
  meraki_alert:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: present
    default_destinations:
      emails:
        - youremail@yourcorp
        - youremail2@yourcorp
      all_admins: true
      snmp: false
    alerts:
      - alert_type: gatewayDown
        enabled: true
        filters:
          timeout: 60
        alert_destinations:
          emails:
            - youremail@yourcorp
            - youremail2@yourcorp
          all_admins: true
          snmp: false
      - alert_type: usageAlert
        enabled: true
        filters:
          period: 1200
          threshold: 104857600
        alert_destinations:
          emails:
            - youremail@yourcorp
            - youremail2@yourcorp
          all_admins: true
          snmp: false
- name: Query all settings
  meraki_alert:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: query
  delegate_to: localhost
"""

RETURN = r"""
data:
    description: Information about the created or manipulated object.
    returned: info
    type: complex
    contains:
        default_destinations:
            description: Properties for destinations when alert specific destinations aren't specified.
            returned: success
            type: complex
            contains:
                all_admins:
                    description: If true, all network admins will receive emails.
                    type: bool
                    sample: true
                    returned: success
                snmp:
                    description: If true, then an SNMP trap will be sent if there is an SNMP trap server configured for this network.
                    type: bool
                    sample: true
                    returned: success
                emails:
                    description: A list of emails that will recieve the alert(s).
                    type: list
                    returned: success
                http_server_ids:
                    description: A list of HTTP server IDs to send a Webhook to.
                    type: list
                    returned: success
        alerts:
            description: Alert-specific configuration for each type.
            type: complex
            contains:
                alert_type:
                    description: The type of alert.
                    type: str
                    returned: success
                enabled:
                    description: A boolean depicting if the alert is turned on or off.
                    type: bool
                    returned: success
                filters:
                    description:
                    - A hash of specific configuration data for the alert. Only filters specific to the alert will be updated.
                    - No validation checks occur against C(filters).
                    type: complex
                    returned: success
                alert_destinations:
                    description: A hash of destinations for this specific alert.
                    type: complex
                    contains:
                        all_admins:
                            description: If true, all network admins will receive emails.
                            type: bool
                            returned: success
                        snmp:
                            description: If true, then an SNMP trap will be sent if there is an SNMP trap server configured for this network.
                            type: bool
                            returned: success
                        emails:
                            description: A list of emails that will recieve the alert(s).
                            type: list
                            returned: success
                        http_server_ids:
                            description: A list of HTTP server IDs to send a Webhook to.
                            type: list
                            returned: success
"""

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import (
    MerakiModule,
    meraki_argument_spec,
)


def get_alert_by_type(type, meraki):
    for alert in meraki.params["alerts"]:
        if alert["alert_type"] == type:
            return alert
    return None


def construct_payload(meraki, current):
    payload = {}
    if meraki.params["default_destinations"] is not None:
        payload["defaultDestinations"] = {}
        if meraki.params["default_destinations"]["all_admins"] is not None:
            payload["defaultDestinations"]["allAdmins"] = meraki.params["default_destinations"]["all_admins"]
        if meraki.params["default_destinations"]["snmp"] is not None:
            payload["defaultDestinations"]["snmp"] = meraki.params["default_destinations"]["snmp"]
        if meraki.params["default_destinations"]["emails"] is not None:
            payload["defaultDestinations"]["emails"] = meraki.params["default_destinations"]["emails"]
            if len(payload["defaultDestinations"]["emails"]) > 0 and payload["defaultDestinations"]["emails"][0] == "None":
                # Ansible is setting the first item to be "None" so we need to clear this
                # This happens when an empty list is provided to clear emails
                del payload["defaultDestinations"]["emails"][0]
        if meraki.params["default_destinations"]["http_server_ids"] is not None:
            payload["defaultDestinations"]["httpServerIds"] = meraki.params["default_destinations"]["http_server_ids"]
            if len(payload["defaultDestinations"]["httpServerIds"]) > 0 and payload["defaultDestinations"]["httpServerIds"][0] == "None":
                # Ansible is setting the first item to be "None" so we need to clear this
                # This happens when an empty list is provided to clear server IDs
                del payload["defaultDestinations"]["httpServerIds"][0]
    if meraki.params["alerts"] is not None:
        payload["alerts"] = []
        # All data should be resubmitted, otherwise it will clear the alert
        # Also, the order matters so it should go in the same order as current
        modified_types = [type["alert_type"] for type in meraki.params["alerts"]]

        # for alert in meraki.params["alerts"]:
        for current_alert in current["alerts"]:
            if current_alert["type"] not in modified_types:
                payload["alerts"].append(current_alert)
            else:
                alert = get_alert_by_type(current_alert["type"], meraki)
                alert_temp = {"type": None}
                if alert["alert_type"] is not None:
                    alert_temp["type"] = alert["alert_type"]
                if alert["enabled"] is not None:
                    alert_temp["enabled"] = alert["enabled"]
                if alert["filters"] is not None:
                    alert_temp["filters"] = alert["filters"]
                if alert["alert_destinations"] is not None:
                    alert_temp["alertDestinations"] = dict()
                    if alert["alert_destinations"]["all_admins"] is not None:
                        alert_temp["alertDestinations"]["allAdmins"] = alert["alert_destinations"]["all_admins"]
                    if alert["alert_destinations"]["snmp"] is not None:
                        alert_temp["alertDestinations"]["snmp"] = alert["alert_destinations"]["snmp"]
                    if alert["alert_destinations"]["emails"] is not None:
                        alert_temp["alertDestinations"]["emails"] = alert["alert_destinations"]["emails"]
                        if len(alert_temp["alertDestinations"]["emails"]) > 0 and alert_temp["alertDestinations"]["emails"][0] == "None":
                            # Ansible is setting the first item to be "None" so we need to clear this
                            # This happens when an empty list is provided to clear emails
                            del alert_temp["defaultDestinations"]["emails"][0]
                    if alert["alert_destinations"]["http_server_ids"] is not None:
                        alert_temp["alertDestinations"]["httpServerIds"] = alert["alert_destinations"]["http_server_ids"]
                        if len(alert_temp["alertDestinations"]["httpServerIds"]) > 0 and alert_temp["alertDestinations"]["httpServerIds"][0] == "None":
                            # Ansible is setting the first item to be "None" so we need to clear this
                            # This happens when an empty list is provided to clear server IDs
                            del alert_temp["defaultDestinations"]["httpServerIds"][0]
                payload["alerts"].append(alert_temp)
    return payload


def main():

    # define the available arguments/parameters that a user can pass to
    # the module

    destinations_arg_spec = dict(
        all_admins=dict(type="bool"),
        snmp=dict(type="bool"),
        emails=dict(type="list", elements="str"),
        http_server_ids=dict(type="list", elements="str"),
    )

    alerts_arg_spec = dict(
        alert_type=dict(type="str"),
        enabled=dict(type="bool"),
        alert_destinations=dict(
            type="dict", default=None, options=destinations_arg_spec
        ),
        filters=dict(type="raw", default={}),
    )

    argument_spec = meraki_argument_spec()
    argument_spec.update(
        net_id=dict(type="str"),
        net_name=dict(type="str", aliases=["name", "network"]),
        state=dict(type="str", choices=["present", "query"], default="present"),
        default_destinations=dict(
            type="dict", default=None, options=destinations_arg_spec
        ),
        alerts=dict(type="list", elements="dict", options=alerts_arg_spec),
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    meraki = MerakiModule(module, function="alert")
    module.params["follow_redirects"] = "all"

    query_urls = {"alert": "/networks/{net_id}/alerts/settings"}
    update_urls = {"alert": "/networks/{net_id}/alerts/settings"}
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
        payload = construct_payload(meraki, original)
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
