#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2021, Mark Mercado <mamercad@gmail.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: digital_ocean_monitoring_alerts_info
version_added: 1.10.0
short_description: Programmatically retrieve metrics as well as configure alert policies based on these metrics
description:
    - The DigitalOcean Monitoring API makes it possible to programmatically retrieve metrics as well as configure alert policies based on these metrics.
    - The Monitoring API can help you gain insight into how your apps are performing and consuming resources.
author: "Mark Mercado (@mamercad)"
options:
  state:
    description:
      - C(present) to return alerts
    type: str
    choices: ["present"]
    default: present
  oauth_token:
    description:
      - DigitalOcean OAuth token; can be specified in C(DO_API_KEY), C(DO_API_TOKEN), or C(DO_OAUTH_TOKEN) environment variables
    type: str
    aliases: ["API_TOKEN"]
    required: true
  uuid:
    description:
      - Alert uuid (if specified only returns the specific alert policy)
    type: str
    required: false
"""


EXAMPLES = r"""
- name: Get Droplet Monitoring alerts polices
  community.digitalocean.digital_ocean_monitoring_alerts_info:
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
  register: monitoring_alerts

- name: Get specific Droplet Monitoring alerts policy
  community.digitalocean.digital_ocean_monitoring_alerts_info:
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    uuid: ec48b0e7-23bb-4a7f-95f2-d83da62fcd60
  register: monitoring_alert
"""


RETURN = r"""
data:
  description: DigitalOcean Monitoring alerts policies
  returned: changed
  type: dict
  sample:
    data:
    - alerts:
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
      uuid: ec48b0e7-23bb-4a7f-95f2-d83da62fcd60
      value: 3.14159
      window: 5m
"""


from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)


class DOMonitoringAlertsInfo(object):
    def __init__(self, module):
        self.rest = DigitalOceanHelper(module)
        self.module = module
        # Pop these values so we don't include them in the POST data
        self.module.params.pop("oauth_token")

    def get_alerts(self):
        alerts = self.rest.get_paginated_data(
            base_url="monitoring/alerts?", data_key_name="policies"
        )
        self.module.exit_json(
            changed=False,
            data=alerts,
        )

    def get_alert(self, uuid):
        alerts = self.rest.get_paginated_data(
            base_url="monitoring/alerts?", data_key_name="policies"
        )
        for alert in alerts:
            alert_uuid = alert.get("uuid", None)
            if alert_uuid is not None:
                if alert_uuid == uuid:
                    self.module.exit_json(
                        changed=False,
                        data=alert,
                    )
            else:
                self.module.fail_json(
                    changed=False, msg="Unexpected error; please file a bug: get_alert"
                )
        self.module.exit_json(
            changed=False,
            data=[],
        )


def run(module):
    alerts = DOMonitoringAlertsInfo(module)
    uuid = module.params.get("uuid", None)
    if uuid is None:
        alerts.get_alerts()
    else:
        alerts.get_alert(uuid)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(choices=["present"], default="present"),
            oauth_token=dict(
                aliases=["API_TOKEN"],
                no_log=True,
                fallback=(
                    env_fallback,
                    ["DO_API_TOKEN", "DO_API_KEY", "DO_OAUTH_TOKEN"],
                ),
                required=True,
            ),
            uuid=dict(type="str", required=False),
        ),
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
