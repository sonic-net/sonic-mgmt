#!/usr/bin/python
# -*- coding: utf-8 -*-
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: grafana_notification_channel
notes:
- Notification channels are replaced by contact points starting Grafana 8.3 and this module is currently not able to manage contact points.
- The module will report execution as successful since Grafana maintains backward compatibility with previous alert management, but
- nothing will be visible in the contact points if new alerting mechanism is enabled.
author:
  - Aliaksandr Mianzhynski (@amenzhinsky)
  - Rémi REY (@rrey)
version_added: "1.1.0"
short_description: Manage Grafana Notification Channels
description:
  - Create/Update/Delete Grafana Notification Channels via API.
deprecated:
  removed_in: "3.0.0"
  why: Legacy alerting is removed in Grafana version 11.
  alternative: Use M(community.grafana.grafana_contact_point) instead.
options:
  org_id:
    description:
      - The Grafana Organisation ID where the dashboard will be imported / exported.
      - Not used when I(grafana_api_key) is set, because the grafana_api_key only belongs to one organisation..
    default: 1
    type: int
  state:
    type: str
    default: present
    choices:
      - present
      - absent
    description:
      - Status of the notification channel.
  uid:
    type: str
    description:
      - The channel unique identifier.
  name:
    type: str
    description:
      - The name of the notification channel.
      - Required when I(state) is C(present).
  type:
    type: str
    choices:
      - dingding
      - discord
      - email
      - googlechat
      - hipchat
      - kafka
      - line
      - teams
      - opsgenie
      - pagerduty
      - prometheus
      - pushover
      - sensu
      - slack
      - telegram
      - threema
      - victorops
      - webhook
    description:
      - The channel notification type.
      - Required when I(state) is C(present).
  is_default:
    type: bool
    default: false
    description:
      - Use this channel for all alerts.
  include_image:
    type: bool
    default: false
    description:
      - Capture a visualization image and attach it to notifications.
  disable_resolve_message:
    type: bool
    default: false
    description:
      - Disable the resolve message.
  skip_version_check:
    description:
      - Skip Grafana version check and try to reach api endpoint anyway.
    type: bool
    default: false
  reminder_frequency:
    type: str
    description:
      - Additional notifications interval for triggered alerts.
      - For example C(15m).
  dingding_url:
    type: str
    description:
      - DingDing webhook URL.
  dingding_message_type:
    type: list
    elements: str
    choices:
      - link
      - action_card
    description:
      - DingDing message type.
  discord_url:
    type: str
    description:
      - Discord webhook URL.
  discord_message_content:
    type: str
    description:
      - Overrides message content.
  email_addresses:
    type: list
    elements: str
    description:
      - List of recipients.
  email_single:
    type: bool
    description:
      - Send single email to all recipients.
  googlechat_url:
    type: str
    description:
      - Google Hangouts webhook URL.
  hipchat_url:
    type: str
    description:
      - HipChat webhook URL.
  hipchat_api_key:
    type: str
    description:
      - HipChat API key.
  hipchat_room_id:
    type: str
    description:
      - HipChat room ID.
  kafka_url:
    type: str
    description:
      - Kafka REST proxy URL.
  kafka_topic:
    type: str
    description:
      - Kafka topic name.
  line_token:
    type: str
    description:
     - LINE token.
  teams_url:
    type: str
    description:
      - Microsoft Teams webhook URL.
  opsgenie_url:
    type: str
    description:
      - OpsGenie webhook URL.
  opsgenie_api_key:
    type: str
    description:
      - OpsGenie API key.
  opsgenie_auto_close:
    type: bool
    description:
      - Automatically close alerts in OpsGenie once the alert goes back to ok.
  opsgenie_override_priority:
    type: bool
    description:
      - Allow the alert priority to be set using the og_priority tag.
  pagerduty_integration_key:
    type: str
    description:
      - PagerDuty integration key.
  pagerduty_severity:
    type: list
    elements: str
    choices:
      - critical
      - error
      - warning
      - info
    description:
      - Alert severity in PagerDuty.
  pagerduty_auto_resolve:
    type: bool
    description:
      - Resolve incidents in PagerDuty once the alert goes back to ok.
  pagerduty_message_in_details:
    type: bool
    description:
      - Move the alert message from the PD summary into the custom details.
      - This changes the custom details object and may break event rules you have configured.
  prometheus_url:
    type: str
    description:
      - Prometheus API URL.
  prometheus_username:
    type: str
    description:
      - Prometheus username.
  prometheus_password:
    type: str
    description:
      - Prometheus password.
  pushover_api_token:
    type: str
    description:
      - Pushover API token.
  pushover_user_key:
    type: str
    description:
      - Pushover user key.
  pushover_devices:
    type: list
    elements: str
    description:
      - Devices list in Pushover.
  pushover_priority:
    type: list
    elements: str
    choices:
      - emergency
      - high
      - normal
      - low
      - lowest
    description:
      - Alert priority in Pushover.
  pushover_retry:
    type: int
    description:
      - Retry in C(n) minutes.
      - Only when priority is C(emergency).
  pushover_expire:
    type: int
    description:
      - Expire alert in C(n) minutes.
      - Only when priority is C(emergency).
  pushover_alert_sound:
    type: str
    description:
      - L(Alert sound in Pushover,https://pushover.net/api#sounds)
  pushover_ok_sound:
    type: str
    description:
      - L(OK sound in Pushover,https://pushover.net/api#sounds)
  sensu_url:
    type: str
    description:
      - Sensu webhook URL.
  sensu_source:
    type: str
    description:
      - Source in Sensu.
  sensu_handler:
    type: str
    description:
      - Sensu handler name.
  sensu_username:
    type: str
    description:
      - Sensu user.
  sensu_password:
    type: str
    description:
      - Sensu password.
  slack_url:
    type: str
    description:
      - Slack webhook URL.
  slack_recipient:
    type: str
    description:
      - Override default Slack channel or user.
  slack_username:
    type: str
    description:
      - Set the username for the bot's message.
  slack_icon_emoji:
    type: str
    description:
      - An emoji to use for the bot's message.
  slack_icon_url:
    type: str
    description:
      - URL to an image to use as the icon for the bot's message
  slack_mention_users:
    type: list
    elements: str
    description:
      - Mention users list.
  slack_mention_groups:
    type: list
    elements: str
    description:
      - Mention groups list.
  slack_mention_channel:
    type: list
    elements: str
    choices:
      - here
      - channel
    description:
      - Mention whole channel or just active members.
  slack_token:
    type: str
    description:
      - Slack token.
  telegram_bot_token:
    type: str
    description:
      - Telegram bot token;
  telegram_chat_id:
    type: str
    description:
      - Telegram chat id.
  threema_gateway_id:
    type: str
    description:
      - 8 character Threema Gateway ID (starting with a *).
  threema_recipient_id:
    type: str
    description:
      - 8 character Threema ID that should receive the alerts.
  threema_api_secret:
    type: str
    description:
      - Threema Gateway API secret.
  victorops_url:
    type: str
    description:
      - VictorOps webhook URL.
  victorops_auto_resolve:
    type: bool
    description:
      - Resolve incidents in VictorOps once the alert goes back to ok.
  webhook_url:
    type: str
    description:
      - Webhook URL
  webhook_username:
    type: str
    description:
      - Webhook username.
  webhook_password:
    type: str
    description:
      - Webhook password.
  webhook_http_method:
    type: list
    elements: str
    choices:
      - POST
      - PUT
    description:
      - Webhook HTTP verb to use.

extends_documentation_fragment:
  - community.grafana.basic_auth
  - community.grafana.api_key
"""


EXAMPLES = """
- name: Create slack notification channel
  register: result
  grafana_notification_channel:
    uid: slack
    name: slack
    type: slack
    slack_url: https://hooks.slack.com/services/xxx/yyy/zzz
    grafana_url: "{{ grafana_url }}"
    grafana_user: "{{ grafana_username }}"
    grafana_password: "{{ grafana_password}}"

- name: Delete slack notification channel
  register: result
  grafana_notification_channel:
    state: absent
    uid: slack
    grafana_url: "{{ grafana_url }}"
    grafana_user: "{{ grafana_username }}"
    grafana_password: "{{ grafana_password}}"
"""

RETURN = """
notification_channel:
  description: Notification channel created or updated by the module.
  returned: changed
  type: dict
  sample: |
    {
      "created": "2020-11-10T21:10:19.675308051+03:00",
      "disableResolveMessage": false,
      "frequency": "",
      "id": 37,
      "isDefault": false,
      "name": "Oops",
      "secureFields": {},
      "sendReminder": false,
      "settings": {
          "uploadImage": false,
          "url": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
      },
      "type": "slack",
      "uid": "slack-oops",
      "updated": "2020-11-10T21:10:19.675308112+03:00"
    }
"""

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_text
from ansible_collections.community.grafana.plugins.module_utils.base import (
    grafana_argument_spec,
    clean_url,
    parse_grafana_version,
)
from ansible.module_utils.urls import basic_auth_header


class GrafanaAPIException(Exception):
    pass


def dingding_channel_payload(data, payload):
    payload["settings"]["url"] = data["dingding_url"]
    if data.get("dingding_message_type"):
        payload["settings"]["msgType"] = {
            "link": "link",
            "action_card": "actionCard",
        }[data["dingding_message_type"]]


def discord_channel_payload(data, payload):
    payload["settings"]["url"] = data["discord_url"]
    if data.get("discord_message_content"):
        payload["settings"]["content"] = data["discord_message_content"]


def email_channel_payload(data, payload):
    payload["settings"]["addresses"] = ";".join(data["email_addresses"])
    if data.get("email_single"):
        payload["settings"]["singleEmail"] = data["email_single"]


def hipchat_channel_payload(data, payload):
    payload["settings"]["url"] = data["hipchat_url"]
    if data.get("hipchat_api_key"):
        payload["settings"]["apiKey"] = data["hipchat_api_key"]
    if data.get("hipchat_room_id"):
        payload["settings"]["roomid"] = data["hipchat_room_id"]


def pagerduty_channel_payload(data, payload):
    payload["settings"]["integrationKey"] = data["pagerduty_integration_key"]
    if data.get("pagerduty_severity"):
        payload["settings"]["severity"] = data["pagerduty_severity"]
    if data.get("pagerduty_auto_resolve"):
        payload["settings"]["autoResolve"] = data["pagerduty_auto_resolve"]
    if data.get("pagerduty_message_in_details"):
        payload["settings"]["messageInDetails"] = data["pagerduty_message_in_details"]


def prometheus_channel_payload(data, payload):
    payload["type"] = "prometheus-alertmanager"
    payload["settings"]["url"] = data["prometheus_url"]
    if data.get("prometheus_username"):
        payload["settings"]["basicAuthUser"] = data["prometheus_username"]
    if data.get("prometheus_password"):
        payload["settings"]["basicAuthPassword"] = data["prometheus_password"]


def pushover_channel_payload(data, payload):
    payload["settings"]["apiToken"] = data["pushover_api_token"]
    payload["settings"]["userKey"] = data["pushover_user_key"]
    if data.get("pushover_devices"):
        payload["settings"]["device"] = ";".join(data["pushover_devices"])
    if data.get("pushover_priority"):
        payload["settings"]["priority"] = {
            "emergency": "2",
            "high": "1",
            "normal": "0",
            "low": "-1",
            "lowest": "-2",
        }[data["pushover_priority"]]
    if data.get("pushover_retry"):
        payload["settings"]["retry"] = str(data["pushover_retry"])
    if data.get("pushover_expire"):
        payload["settings"]["expire"] = str(data["pushover_expire"])
    if data.get("pushover_alert_sound"):
        payload["settings"]["sound"] = data["pushover_alert_sound"]
    if data.get("pushover_ok_sound"):
        payload["settings"]["okSound"] = data["pushover_ok_sound"]


def sensu_channel_payload(data, payload):
    payload["settings"]["url"] = data["sensu_url"]
    if data.get("sensu_source"):
        payload["settings"]["source"] = data["sensu_source"]
    if data.get("sensu_handler"):
        payload["settings"]["handler"] = data["sensu_handler"]
    if data.get("sensu_username"):
        payload["settings"]["username"] = data["sensu_username"]
    if data.get("sensu_password"):
        payload["settings"]["password"] = data["sensu_password"]


def slack_channel_payload(data, payload):
    payload["settings"]["url"] = data["slack_url"]
    if data.get("slack_recipient"):
        payload["settings"]["recipient"] = data["slack_recipient"]
    if data.get("slack_username"):
        payload["settings"]["username"] = data["slack_username"]
    if data.get("slack_icon_emoji"):
        payload["settings"]["iconEmoji"] = data["slack_icon_emoji"]
    if data.get("slack_icon_url"):
        payload["settings"]["iconUrl"] = data["slack_icon_url"]
    if data.get("slack_mention_users"):
        payload["settings"]["mentionUsers"] = ",".join(data["slack_mention_users"])
    if data.get("slack_mention_groups"):
        payload["settings"]["mentionGroups"] = ",".join(data["slack_mention_groups"])
    if data.get("slack_mention_channel"):
        payload["settings"]["mentionChannel"] = data["slack_mention_channel"]
    if data.get("slack_token"):
        payload["settings"]["token"] = data["slack_token"]


def webhook_channel_payload(data, payload):
    payload["settings"]["url"] = data["webhook_url"]
    if data.get("webhook_http_method"):
        payload["settings"]["httpMethod"] = data["webhook_http_method"]
    if data.get("webhook_username"):
        payload["settings"]["username"] = data["webhook_username"]
    if data.get("webhook_password"):
        payload["settings"]["password"] = data["webhook_password"]


def grafana_notification_channel_payload(data):
    payload = {
        "uid": data["uid"],
        "name": data["name"],
        "type": data["type"],
        "isDefault": data["is_default"],
        "disableResolveMessage": data["disable_resolve_message"],
        "settings": {"uploadImage": data["include_image"]},
    }

    if data.get("reminder_frequency"):
        payload["sendReminder"] = True
        payload["frequency"] = data["reminder_frequency"]

    if data["type"] == "dingding":
        dingding_channel_payload(data, payload)
    elif data["type"] == "discord":
        discord_channel_payload(data, payload)
    elif data["type"] == "email":
        email_channel_payload(data, payload)
    elif data["type"] == "googlechat":
        payload["settings"]["url"] = data["googlechat_url"]
    elif data["type"] == "hipchat":
        hipchat_channel_payload(data, payload)
    elif data["type"] == "kafka":
        payload["settings"]["kafkaRestProxy"] = data["kafka_url"]
        payload["settings"]["kafkaTopic"] = data["kafka_topic"]
    elif data["type"] == "line":
        payload["settings"]["token"] = data["line_token"]
    elif data["type"] == "teams":
        payload["settings"]["url"] = data["teams_url"]
    elif data["type"] == "opsgenie":
        payload["settings"]["apiUrl"] = data["opsgenie_url"]
        payload["settings"]["apiKey"] = data["opsgenie_api_key"]
    elif data["type"] == "pagerduty":
        pagerduty_channel_payload(data, payload)
    elif data["type"] == "prometheus":
        prometheus_channel_payload(data, payload)
    elif data["type"] == "pushover":
        pushover_channel_payload(data, payload)
    elif data["type"] == "sensu":
        sensu_channel_payload(data, payload)
    elif data["type"] == "slack":
        slack_channel_payload(data, payload)
    elif data["type"] == "telegram":
        payload["settings"]["bottoken"] = data["telegram_bot_token"]
        payload["settings"]["chatid"] = data["telegram_chat_id"]
    elif data["type"] == "threema":
        payload["settings"]["gateway_id"] = data["threema_gateway_id"]
        payload["settings"]["recipient_id"] = data["threema_recipient_id"]
        payload["settings"]["api_secret"] = data["threema_api_secret"]
    elif data["type"] == "victorops":
        payload["settings"]["url"] = data["victorops_url"]
        if data.get("victorops_auto_resolve"):
            payload["settings"]["autoResolve"] = data["victorops_auto_resolve"]
    elif data["type"] == "webhook":
        webhook_channel_payload(data, payload)
    return payload


class GrafanaNotificationChannelInterface(object):
    def __init__(self, module):
        self._module = module
        # {{{ Authentication header
        self.headers = {"Content-Type": "application/json"}
        if module.params.get("grafana_api_key", None):
            self.headers["Authorization"] = (
                "Bearer %s" % module.params["grafana_api_key"]
            )
        else:
            self.headers["Authorization"] = basic_auth_header(
                module.params["url_username"], module.params["url_password"]
            )
        # }}}
        self.grafana_url = clean_url(module.params.get("url"))
        if module.params.get("skip_version_check") is False:
            try:
                grafana_version = self.get_version()
            except GrafanaAPIException as e:
                self._module.fail_json(failed=True, msg=to_text(e))
            if grafana_version["major"] >= 11:
                self._module.fail_json(
                    failed=True,
                    msg="Legacy Alerting API is available up to Grafana v10",
                )

    def get_version(self):
        r, info = fetch_url(
            self._module,
            "%s/api/health" % self.grafana_url,
            headers=self.headers,
            method="GET",
        )
        if info["status"] == 200:
            version = json.loads(to_text(r.read())).get("version")
            if version is not None:
                return parse_grafana_version(version)
        else:
            raise GrafanaAPIException("Failed to retrieve version: %s" % info)

    def grafana_switch_organisation(self, grafana_url, org_id):
        r, info = fetch_url(
            self._module,
            "%s/api/user/using/%s" % (grafana_url, org_id),
            headers=self.headers,
            method="POST",
        )
        if info["status"] != 200:
            raise GrafanaAPIException(
                "Unable to switch to organization %s : %s" % (org_id, info)
            )

    def grafana_create_notification_channel(self, data, payload):
        r, info = fetch_url(
            self._module,
            "%s/api/alert-notifications" % data["url"],
            data=json.dumps(payload),
            headers=self.headers,
            method="POST",
        )
        if info["status"] == 200:
            return {
                "state": "present",
                "changed": True,
                "channel": json.loads(to_text(r.read())),
            }
        else:
            raise GrafanaAPIException(
                "Unable to create notification channel: %s" % info
            )

    def grafana_update_notification_channel(self, data, payload, before):
        r, info = fetch_url(
            self._module,
            "%s/api/alert-notifications/uid/%s" % (data["url"], data["uid"]),
            data=json.dumps(payload),
            headers=self.headers,
            method="PUT",
        )
        if info["status"] == 200:
            del before["created"]
            del before["updated"]

            channel = json.loads(to_text(r.read()))
            after = channel.copy()
            del after["created"]
            del after["updated"]

            if before == after:
                return {
                    "changed": False,
                    "channel": channel,
                }
            else:
                return {
                    "changed": True,
                    "diff": {
                        "before": before,
                        "after": after,
                    },
                    "channel": channel,
                }
        else:
            raise GrafanaAPIException(
                "Unable to update notification channel %s : %s" % (data["uid"], info)
            )

    def grafana_create_or_update_notification_channel(self, data):
        payload = grafana_notification_channel_payload(data)
        r, info = fetch_url(
            self._module,
            "%s/api/alert-notifications/uid/%s" % (data["url"], data["uid"]),
            headers=self.headers,
        )
        if info["status"] == 200:
            before = json.loads(to_text(r.read()))
            return self.grafana_update_notification_channel(data, payload, before)
        elif info["status"] == 404:
            return self.grafana_create_notification_channel(data, payload)
        else:
            raise GrafanaAPIException(
                "Unable to get notification channel %s : %s" % (data["uid"], info)
            )

    def grafana_delete_notification_channel(self, data):
        r, info = fetch_url(
            self._module,
            "%s/api/alert-notifications/uid/%s" % (data["url"], data["uid"]),
            headers=self.headers,
            method="DELETE",
        )
        if info["status"] == 200:
            return {"state": "absent", "changed": True}
        elif info["status"] == 404:
            return {"changed": False}
        else:
            raise GrafanaAPIException(
                "Unable to delete notification channel %s : %s" % (data["uid"], info)
            )


def main():
    argument_spec = grafana_argument_spec()
    argument_spec.update(
        org_id=dict(type="int", default=1),
        uid=dict(type="str"),
        name=dict(type="str"),
        type=dict(
            type="str",
            choices=[
                "dingding",
                "discord",
                "email",
                "googlechat",
                "hipchat",
                "kafka",
                "line",
                "teams",
                "opsgenie",
                "pagerduty",
                "prometheus",
                "pushover",
                "sensu",
                "slack",
                "telegram",
                "threema",
                "victorops",
                "webhook",
            ],
        ),
        is_default=dict(type="bool", default=False),
        include_image=dict(type="bool", default=False),
        disable_resolve_message=dict(type="bool", default=False),
        skip_version_check=dict(type="bool", default=False),
        reminder_frequency=dict(type="str"),
        dingding_url=dict(type="str"),
        dingding_message_type=dict(
            type="list", elements="str", choices=["link", "action_card"]
        ),
        discord_url=dict(type="str"),
        discord_message_content=dict(type="str"),
        email_addresses=dict(type="list", elements="str"),
        email_single=dict(type="bool"),
        googlechat_url=dict(type="str"),
        hipchat_url=dict(type="str"),
        hipchat_api_key=dict(type="str", no_log=True),
        hipchat_room_id=dict(type="str"),
        kafka_url=dict(type="str"),
        kafka_topic=dict(type="str"),
        line_token=dict(type="str", no_log=True),
        teams_url=dict(type="str"),
        opsgenie_url=dict(type="str"),
        opsgenie_api_key=dict(type="str", no_log=True),
        opsgenie_auto_close=dict(type="bool"),
        opsgenie_override_priority=dict(type="bool"),
        pagerduty_integration_key=dict(type="str", no_log=True),
        pagerduty_severity=dict(
            type="list",
            elements="str",
            choices=["critical", "error", "warning", "info"],
        ),
        pagerduty_auto_resolve=dict(type="bool"),
        pagerduty_message_in_details=dict(type="bool"),
        prometheus_url=dict(type="str"),
        prometheus_username=dict(type="str"),
        prometheus_password=dict(type="str", no_log=True),
        pushover_api_token=dict(type="str", no_log=True),
        pushover_user_key=dict(type="str", no_log=True),
        pushover_devices=dict(type="list", elements="str"),
        pushover_priority=dict(
            type="list",
            elements="str",
            choices=["emergency", "high", "normal", "low", "lowest"],
        ),
        pushover_retry=dict(type="int"),  # TODO: only when priority==emergency
        pushover_expire=dict(type="int"),  # TODO: only when priority==emergency
        pushover_alert_sound=dict(type="str"),  # TODO: add sound choices
        pushover_ok_sound=dict(type="str"),  # TODO: add sound choices
        sensu_url=dict(type="str"),
        sensu_source=dict(type="str"),
        sensu_handler=dict(type="str"),
        sensu_username=dict(type="str"),
        sensu_password=dict(type="str", no_log=True),
        slack_url=dict(type="str", no_log=True),
        slack_recipient=dict(type="str"),
        slack_username=dict(type="str"),
        slack_icon_emoji=dict(type="str"),
        slack_icon_url=dict(type="str"),
        slack_mention_users=dict(type="list", elements="str"),
        slack_mention_groups=dict(type="list", elements="str"),
        slack_mention_channel=dict(
            type="list", elements="str", choices=["here", "channel"]
        ),
        slack_token=dict(type="str", no_log=True),
        telegram_bot_token=dict(type="str", no_log=True),
        telegram_chat_id=dict(type="str"),
        threema_gateway_id=dict(type="str"),
        threema_recipient_id=dict(type="str"),
        threema_api_secret=dict(type="str", no_log=True),
        victorops_url=dict(type="str"),
        victorops_auto_resolve=dict(type="bool"),
        webhook_url=dict(type="str"),
        webhook_username=dict(type="str"),
        webhook_password=dict(type="str", no_log=True),
        webhook_http_method=dict(type="list", elements="str", choices=["POST", "PUT"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=[
            ["url_username", "url_password", "org_id"],
            ["prometheus_username", "prometheus_password"],
            ["sensu_username", "sensu_password"],
        ],
        mutually_exclusive=[["url_username", "grafana_api_key"]],
        required_if=[
            ["state", "present", ["name", "type"]],
            ["type", "dingding", ["dingding_url"]],
            ["type", "discord", ["discord_url"]],
            ["type", "email", ["email_addresses"]],
            ["type", "googlechat", ["googlechat_url"]],
            ["type", "hipchat", ["hipchat_url"]],
            ["type", "kafka", ["kafka_url", "kafka_topic"]],
            ["type", "line", ["line_token"]],
            ["type", "teams", ["teams_url"]],
            ["type", "opsgenie", ["opsgenie_url", "opsgenie_api_key"]],
            ["type", "pagerduty", ["pagerduty_integration_key"]],
            ["type", "prometheus", ["prometheus_url"]],
            ["type", "pushover", ["pushover_api_token", "pushover_user_key"]],
            ["type", "sensu", ["sensu_url"]],
            ["type", "slack", ["slack_url"]],
            ["type", "telegram", ["telegram_bot_token", "telegram_chat_id"]],
            [
                "type",
                "threema",
                ["threema_gateway_id", "threema_recipient_id", "threema_api_secret"],
            ],
            ["type", "victorops", ["victorops_url"]],
            ["type", "webhook", ["webhook_url"]],
        ],
    )

    module.params["url"] = clean_url(module.params["url"])
    alert_channel_iface = GrafanaNotificationChannelInterface(module)

    if module.params["state"] == "present":
        result = alert_channel_iface.grafana_create_or_update_notification_channel(
            module.params
        )
        module.exit_json(failed=False, **result)
    else:
        result = alert_channel_iface.grafana_delete_notification_channel(module.params)
        module.exit_json(failed=False, **result)


if __name__ == "__main__":
    main()
