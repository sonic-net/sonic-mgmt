#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2021, Mark Mercado <mamercad@gmail.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: digital_ocean_monitoring_alerts
version_added: 1.10.0
short_description: Programmatically retrieve metrics as well as configure alert policies based on these metrics
description:
    - The DigitalOcean Monitoring API makes it possible to programmatically retrieve metrics as well as configure alert policies based on these metrics.
    - The Monitoring API can help you gain insight into how your apps are performing and consuming resources.
author: "Mark Mercado (@mamercad)"
options:
  oauth_token:
    description:
      - DigitalOcean OAuth token; can be specified in C(DO_API_KEY), C(DO_API_TOKEN), or C(DO_OAUTH_TOKEN) environment variables
    type: str
    aliases: ["API_TOKEN"]
    required: true
  state:
    description:
      - The usual, C(present) to create, C(absent) to destroy
    type: str
    choices: ["present", "absent"]
    default: present
  alerts:
    description:
      - Alert object, required for C(state=present)
      - Supports C(email["email1", "email2", ...]) and C(slack[{"channel1", "url1"}, {"channel2", "url2"}, ...])
    type: dict
    required: false
  compare:
    description: Alert comparison, required for C(state=present)
    type: str
    required: false
    choices: ["GreaterThan", "LessThan"]
  description:
    description: Alert description, required for C(state=present)
    type: str
    required: false
  enabled:
    description: Enabled or not, required for C(state=present)
    type: bool
    required: false
  entities:
    description: Alert entities, required for C(state=present)
    type: list
    elements: str
    required: false
  tags:
    description: Alert tags, required for C(state=present)
    type: list
    elements: str
    required: false
  type:
    description:
      - Alert type, required for C(state=present)
      - See U(https://docs.digitalocean.com/reference/api/api-reference/#operation/create_alert_policy) for valid types
    type: str
    required: false
    choices:
      - v1/insights/droplet/load_1
      - v1/insights/droplet/load_5
      - v1/insights/droplet/load_15
      - v1/insights/droplet/memory_utilization_percent
      - v1/insights/droplet/disk_utilization_percent
      - v1/insights/droplet/cpu
      - v1/insights/droplet/disk_read
      - v1/insights/droplet/disk_write
      - v1/insights/droplet/public_outbound_bandwidth
      - v1/insights/droplet/public_inbound_bandwidth
      - v1/insights/droplet/private_outbound_bandwidth
      - v1/insights/droplet/private_inbound_bandwidth
  value:
    description: Alert threshold, required for C(state=present)
    type: float
    required: false
  window:
    description: Alert window, required for C(state=present)
    type: str
    choices: ["5m", "10m", "30m", "1h"]
    required: false
  uuid:
    description: Alert uuid, required for C(state=absent)
    type: str
    required: false
"""


EXAMPLES = r"""
- name: Create Droplet Monitoring alerts policy
  community.digitalocean.digital_ocean_monitoring_alerts:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    alerts:
      email: ["alerts@example.com"]
      slack: []
    compare: GreaterThan
    description: Droplet load1 alert
    enabled: true
    entities: ["{{ droplet_id }}"]
    tags: ["my_alert_tag"]
    type: v1/insights/droplet/load_1
    value: 3.14159
    window: 5m
  register: monitoring_alert_policy

- name: Delete Droplet Monitoring alerts policy
  community.digitalocean.digital_ocean_monitoring_alerts:
    state: absent
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    uuid: "{{ monitoring_alert_policy.data.uuid }}"
"""


RETURN = r"""
data:
  description: A DigitalOcean Monitoring alerts policy
  returned: changed
  type: dict
  sample:
    alerts:
      email:
      - mamercad@gmail.com
      slack: []
    compare: GreaterThan
    description: Droplet load1 alert
    enabled: true
    entities:
    - '262383737'
    tags:
    - my_alert_tag
    type: v1/insights/droplet/load_1
    uuid: 9f988f00-4690-443d-b638-ed5a99bbad3b
    value: 3.14159
    window: 5m
"""


from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)


alert_types = [
    "v1/insights/droplet/load_1",
    "v1/insights/droplet/load_5",
    "v1/insights/droplet/load_15",
    "v1/insights/droplet/memory_utilization_percent",
    "v1/insights/droplet/disk_utilization_percent",
    "v1/insights/droplet/cpu",
    "v1/insights/droplet/disk_read",
    "v1/insights/droplet/disk_write",
    "v1/insights/droplet/public_outbound_bandwidth",
    "v1/insights/droplet/public_inbound_bandwidth",
    "v1/insights/droplet/private_outbound_bandwidth",
    "v1/insights/droplet/private_inbound_bandwidth",
]

alert_keys = [
    "alerts",
    "compare",
    "description",
    "enabled",
    "entities",
    "tags",
    "type",
    "value",
    "window",
]

alert_windows = ["5m", "10m", "30m", "1h"]


class DOMonitoringAlerts(object):
    def __init__(self, module):
        self.rest = DigitalOceanHelper(module)
        self.module = module
        # Pop these values so we don't include them in the POST data
        self.module.params.pop("oauth_token")

    def get_alerts(self):
        alerts = self.rest.get_paginated_data(
            base_url="monitoring/alerts?", data_key_name="policies"
        )
        return alerts

    def get_alert(self):
        alerts = self.rest.get_paginated_data(
            base_url="monitoring/alerts?", data_key_name="policies"
        )
        for alert in alerts:
            for alert_key in alert_keys:
                if alert.get(alert_key, None) != self.module.params.get(
                    alert_key, None
                ):
                    break  # This key doesn't match, try the next alert.
            else:
                return alert  # Didn't hit break, this alert matches.
        return None

    def create(self):
        # Check for an existing (same) one.
        alert = self.get_alert()
        if alert is not None:
            self.module.exit_json(
                changed=False,
                data=alert,
            )

        # Check mode
        if self.module.check_mode:
            self.module.exit_json(changed=True)

        # Create it.
        request_params = dict(self.module.params)
        response = self.rest.post("monitoring/alerts", data=request_params)
        if response.status_code == 200:
            alert = self.get_alert()
            if alert is not None:
                self.module.exit_json(
                    changed=True,
                    data=alert,
                )
            else:
                self.module.fail_json(
                    changed=False, msg="Unexpected error; please file a bug: create"
                )
        else:
            self.module.fail_json(
                msg="Create Monitoring Alert '{0}' failed [HTTP {1}: {2}]".format(
                    self.module.params.get("description"),
                    response.status_code,
                    response.json.get("message", None),
                )
            )

    def delete(self):
        uuid = self.module.params.get("uuid", None)
        if uuid is not None:
            # Check mode
            if self.module.check_mode:
                self.module.exit_json(changed=True)

            # Delete it
            response = self.rest.delete("monitoring/alerts/{0}".format(uuid))
            if response.status_code == 204:
                self.module.exit_json(
                    changed=True,
                    msg="Deleted Monitoring Alert {0}".format(uuid),
                )
            else:
                self.module.fail_json(
                    msg="Delete Monitoring Alert {0} failed [HTTP {1}: {2}]".format(
                        uuid,
                        response.status_code,
                        response.json.get("message", None),
                    )
                )
        else:
            self.module.fail_json(
                changed=False, msg="Unexpected error; please file a bug: delete"
            )


def run(module):
    state = module.params.pop("state")
    alerts = DOMonitoringAlerts(module)
    if state == "present":
        alerts.create()
    else:
        alerts.delete()


def main():
    module = AnsibleModule(
        argument_spec=dict(
            oauth_token=dict(
                aliases=["API_TOKEN"],
                no_log=True,
                fallback=(
                    env_fallback,
                    ["DO_API_TOKEN", "DO_API_KEY", "DO_OAUTH_TOKEN"],
                ),
                required=True,
            ),
            state=dict(
                choices=["present", "absent"], default="present", required=False
            ),
            alerts=dict(type="dict", required=False),
            compare=dict(
                type="str", choices=["GreaterThan", "LessThan"], required=False
            ),
            description=dict(type="str", required=False),
            enabled=dict(type="bool", required=False),
            entities=dict(type="list", elements="str", required=False),
            tags=dict(type="list", elements="str", required=False),
            type=dict(type="str", choices=alert_types, required=False),
            value=dict(type="float", required=False),
            window=dict(type="str", choices=alert_windows, required=False),
            uuid=dict(type="str", required=False),
        ),
        required_if=(
            [
                ("state", "present", alert_keys),
                ("state", "absent", ["uuid"]),
            ]
        ),
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
