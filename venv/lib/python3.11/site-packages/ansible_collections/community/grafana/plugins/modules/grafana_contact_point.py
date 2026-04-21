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
module: grafana_contact_point
author:
  - Moritz Pötschk (@nemental)
version_added: "2.0.0"
short_description: Manage Grafana Contact Points
description:
  - Create/Update/Delete Grafana Contact Points via API.
options:
  disable_resolve_message:
    description:
      - Disables the resolve message.
    type: bool
    default: false
  include_image:
    description:
      - Whether to include an image in the notification.
    type: bool
    default: false
  name:
    description:
      - The name of the contact point.
      - Required when C(state) is C(present).
    type: str
  org_id:
    description:
      - The organization ID.
    type: int
    default: 1
  org_name:
    description:
      - The name of the organization.
    type: str
  provisioning:
    description:
      - Indicates if provisioning is enabled.
    type: bool
    default: true
  state:
    description:
      - Status of the contact point.
    type: str
    default: present
    choices:
      - present
      - absent
  type:
    description:
      - The type of the contact point.
      - Required when C(state) is C(present).
    type: str
    choices:
      - alertmanager
      - dingding
      - discord
      - email
      - googlechat
      - kafka
      - line
      - opsgenie
      - pagerduty
      - pushover
      - sensugo
      - slack
      - teams
      - telegram
      - threema
      - victorops
      - webex
      - webhook
      - wecom
  uid:
    description:
      - The unique ID of the contact point.
      - Normally the uid is generated randomly, but it is required for handling the contact point via API.
    type: str
    required: true
  alertmanager_password:
    description:
      - Password for accessing Alertmanager.
    type: str
  alertmanager_url:
    description:
      - URL for accessing Alertmanager.
      - Required when C(type) is C(alertmanager).
    type: str
  alertmanager_username:
    description:
      - Username for accessing Alertmanager.
    type: str
  dingding_message:
    description:
      - The message to send via DingDing.
    type: str
  dingding_message_type:
    description:
      - The type of message to send via DingDing.
    type: str
  dingding_title:
    description:
      - The title of the DingDing message.
    type: str
  dingding_url:
    description:
      - The URL for DingDing webhook.
      - Required when C(type) is C(dingding).
    type: str
  discord_avatar_url:
    description:
      - The avatar URL for Discord messages.
    type: str
  discord_message:
    description:
      - The message to send via Discord.
    type: str
  discord_title:
    description:
      - The title of the Discord message.
    type: str
  discord_url:
    description:
      - The URL for Discord webhook.
      - Required when C(type) is C(discord).
    type: str
  discord_use_username:
    description:
      - Whether to use a custom username in Discord.
    type: bool
    default: false
  email_addresses:
    description:
      - List of email addresses to send the message to.
      - Required when C(type) is C(email).
    type: list
    elements: str
  email_message:
    description:
      - The content of the email message.
    type: str
  email_single:
    description:
      - Whether to send a single email or individual emails.
    type: bool
    default: false
  email_subject:
    description:
      - The subject of the email.
    type: str
  googlechat_url:
    description:
      - The URL for Google Chat webhook.
      - Required when C(type) is C(webhook).
    type: str
  googlechat_message:
    description:
      - The message to send via Google Chat.
    type: str
  googlechat_title:
    description:
      - The title of the Google Chat message.
    type: str
  kafka_api_version:
    description:
      - The API version for Kafka.
    type: str
    default: v2
  kafka_cluster_id:
    description:
      - The cluster ID for Kafka.
    type: str
  kafka_description:
    description:
      - The description for the Kafka configuration.
    type: str
  kafka_details:
    description:
      - Additional details for Kafka.
    type: str
  kafka_password:
    description:
      - Password for accessing Kafka.
    type: str
  kafka_rest_proxy_url:
    description:
      - URL for Kafka REST Proxy.
      - Required when C(type) is C(kafka).
    type: str
  kafka_topic:
    description:
      - Kafka topic to publish to.
      - Required when C(type) is C(kafka).
    type: str
  kafka_username:
    description:
      - Username for accessing Kafka.
    type: str
  line_description:
    description:
      - Description for the Line message.
    type: str
  line_title:
    description:
      - Title of the Line message.
    type: str
  line_token:
    description:
      - Access token for Line.
      - Required when C(type) is C(line).
    type: str
  opsgenie_api_key:
    description:
      - API key for OpsGenie.
      - Required when C(type) is C(opsgenie).
    type: str
  opsgenie_auto_close:
    description:
      - Whether to enable auto-closing of alerts in OpsGenie.
    type: bool
  opsgenie_description:
    description:
      - Description of the OpsGenie alert.
    type: str
  opsgenie_message:
    description:
      - Message to send via OpsGenie.
    type: str
  opsgenie_override_priority:
    description:
      - Whether to override the priority in OpsGenie.
    type: bool
  opsgenie_responders:
    description:
      - List of responders for OpsGenie alerts.
    type: list
    elements: dict
  opsgenie_send_tags_as:
    description:
      - Format for sending tags in OpsGenie.
    type: str
  opsgenie_url:
    description:
      - URL for OpsGenie webhook.
      - Required when C(type) is C(pagerduty).
    type: str
  pagerduty_class:
    description:
      - Class of the PagerDuty alert.
    type: str
  pagerduty_client:
    description:
      - Client identifier for PagerDuty.
    type: str
  pagerduty_client_url:
    description:
      - Client URL for PagerDuty.
    type: str
  pagerduty_component:
    description:
      - Component involved in the PagerDuty alert.
    type: str
  pagerduty_details:
    description:
      - List of additional details for PagerDuty.
    type: list
    elements: dict
  pagerduty_group:
    description:
      - Group associated with the PagerDuty alert.
    type: str
  pagerduty_integration_key:
    description:
      - Integration key for PagerDuty.
      - Required when C(type) is C(pagerduty).
    type: str
  pagerduty_severity:
    description:
      - Severity level of the PagerDuty alert.
    type: str
    choices:
      - critical
      - error
      - warning
      - info
  pagerduty_source:
    description:
      - Source of the PagerDuty alert.
    type: str
  pagerduty_summary:
    description:
      - Summary of the PagerDuty alert.
    type: str
  pushover_api_token:
    description:
      - API token for Pushover.
      - Required when C(type) is C(pushover).
    type: str
  pushover_devices:
    description:
      - List of devices for Pushover notifications.
    type: list
    elements: str
  pushover_expire:
    description:
      - Expiration time for Pushover notifications.
    type: int
  pushover_message:
    description:
      - Message to send via Pushover.
    type: str
  pushover_ok_priority:
    description:
      - Priority for OK messages in Pushover.
    type: int
  pushover_ok_sound:
    description:
      - Sound for OK messages in Pushover.
    type: str
  pushover_priority:
    description:
      - Priority for Pushover messages.
    type: int
  pushover_retry:
    description:
      - Retry interval for Pushover messages.
    type: int
  pushover_sound:
    description:
      - Sound for Pushover notifications.
    type: str
  pushover_title:
    description:
      - Title of the Pushover message.
    type: str
  pushover_upload_image:
    description:
      - Whether to upload an image with Pushover notification.
    type: bool
    default: true
  pushover_user_key:
    description:
      - User key for Pushover.
      - Required when C(type) is C(pushover).
    type: str
  sensugo_api_key:
    description:
      - API key for Sensu Go.
      - Required when C(type) is C(pushover).
    type: str
  sensugo_url:
    description:
      - URL for Sensu Go.
      - Required when C(type) is C(sensugo).
    type: str
  sensugo_check:
    description:
      - Check name for Sensu Go.
    type: str
  sensugo_entity:
    description:
      - Entity name for Sensu Go.
    type: str
  sensugo_handler:
    description:
      - Handler for Sensu Go.
    type: str
  sensugo_message:
    description:
      - Message to send via Sensu Go.
    type: str
  sensugo_namespace:
    description:
      - Namespace for Sensu Go.
    type: str
  slack_endpoint_url:
    description:
      - Endpoint URL for Slack webhook.
    type: str
  slack_icon_emoji:
    description:
      - Icon emoji for Slack messages.
    type: str
  slack_icon_url:
    description:
      - Icon URL for Slack messages.
    type: str
  slack_mention_channel:
    description:
      - Channel mention for Slack messages.
    type: str
    choices:
      - here
      - channel
  slack_mention_groups:
    description:
      - List of groups to mention in Slack messages.
    type: list
    elements: str
  slack_mention_users:
    description:
      - List of users to mention in Slack messages.
    type: list
    elements: str
  slack_recipient:
    description:
      - Recipient for Slack messages.
      - Required when C(type) is C(slack).
    type: str
  slack_text:
    description:
      - Text content for Slack messages.
    type: str
  slack_title:
    description:
      - Title of the Slack message.
    type: str
  slack_token:
    description:
      - Token for Slack authentication.
      - Required when C(type) is C(slack).
    type: str
  slack_url:
    description:
      - URL for Slack webhook.
      - Required when C(type) is C(slack).
    type: str
  slack_username:
    description:
      - Username to use in Slack messages.
    type: str
  teams_message:
    description:
      - Message to send via Microsoft Teams.
    type: str
  teams_section_title:
    description:
      - Section title for Microsoft Teams messages.
    type: str
  teams_title:
    description:
      - Title of the Microsoft Teams message.
    type: str
  teams_url:
    description:
      - URL for Microsoft Teams webhook.
      - Required when C(type) is C(teams).
    type: str
  telegram_chat_id:
    description:
      - Chat ID for Telegram.
      - Required when C(type) is C(telegram).
    type: str
  telegram_disable_notifications:
    description:
      - Whether to disable notifications for Telegram messages.
    type: bool
  telegram_message:
    description:
      - Message to send via Telegram.
    type: str
  telegram_parse_mode:
    description:
      - Parse mode for Telegram messages.
    type: str
  telegram_protect_content:
    description:
      - Whether to protect content in Telegram messages.
    type: bool
  telegram_token:
    description:
      - Token for Telegram authentication.
      - Required when C(type) is C(telegram).
    type: str
  telegram_web_page_view:
    description:
      - Whether to enable web page preview in Telegram messages.
    type: bool
  threema_api_secret:
    description:
      - API secret for Threema.
      - Required when C(type) is C(threema).
    type: str
  threema_description:
    description:
      - Description for Threema messages.
    type: str
  threema_gateway_id:
    description:
      - Gateway ID for Threema.
      - Required when C(type) is C(threema).
    type: str
  threema_recipient_id:
    description:
      - Recipient ID for Threema messages.
      - Required when C(type) is C(threema).
    type: str
  threema_title:
    description:
      - Title of the Threema message.
    type: str
  victorops_description:
    description:
      - Description for VictorOps messages.
    type: str
  victorops_message_type:
    description:
      - Message type for VictorOps.
    type: str
    choices:
      - CRITICAL
      - RECOVERY
  victorops_title:
    description:
      - Title of the VictorOps message.
    type: str
  victorops_url:
    description:
      - URL for VictorOps webhook.
      - Required when C(type) is C(victorops).
    type: str
  webex_api_url:
    description:
      - API URL for Webex.
    type: str
  webex_message:
    description:
      - Message to send via Webex.
    type: str
  webex_room_id:
    description:
      - Room ID for Webex messages.
      - Required when C(type) is C(webex).
    type: str
  webex_token:
    description:
      - Token for Webex authentication.
      - Required when C(type) is C(webex).
    type: str
  webhook_authorization_credentials:
    description:
      - Authorization credentials for webhook.
    type: str
  webhook_authorization_scheme:
    description:
      - Authorization scheme for webhook.
    type: str
  webhook_http_method:
    description:
      - HTTP method for webhook.
    type: str
    choices:
      - POST
      - PUT
  webhook_max_alerts:
    description:
      - Maximum number of alerts for webhook.
    type: int
  webhook_message:
    description:
      - Message to send via webhook.
    type: str
  webhook_password:
    description:
      - Password for webhook authentication.
    type: str
  webhook_title:
    description:
      - Title of the webhook message.
    type: str
  webhook_url:
    description:
      - URL for webhook.
      - Required when C(type) is C(webhook).
    type: str
  webhook_username:
    description:
      - Username for webhook authentication.
    type: str
  wecom_agent_id:
    description:
      - Agent ID for WeCom.
      - Required when C(type) is C(wecom).
    type: str
  wecom_corp_id:
    description:
      - Corporate ID for WeCom.
      - Required when C(type) is C(wecom).
    type: str
  wecom_message:
    description:
      - Message to send via WeCom.
    type: str
  wecom_msg_type:
    description:
      - Message type for WeCom.
    type: str
  wecom_secret:
    description:
      - Secret for WeCom authentication.
      - Required when C(type) is C(wecom).
    type: str
  wecom_title:
    description:
      - Title of the WeCom message.
    type: str
  wecom_to_user:
    description:
      - List of users to send the WeCom message to.
    type: list
    elements: str
  wecom_url:
    description:
      - URL for WeCom webhook.
      - Required when C(type) is C(wecom).
    type: str
extends_documentation_fragment:
  - community.grafana.basic_auth
  - community.grafana.api_key
"""


EXAMPLES = """
- name: Create email contact point
  community.grafana.grafana_contact_point:
    grafana_url: "{{ grafana_url }}"
    grafana_user: "{{ grafana_username }}"
    grafana_password: "{{ grafana_password }}"
    uid: email
    name: E-Mail
    type: email
    email_addresses:
      - example@example.com

- name: Delete email contact point
  community.grafana.grafana_contact_point:
    grafana_url: "{{ grafana_url }}"
    grafana_user: "{{ grafana_username }}"
    grafana_password: "{{ grafana_password }}"
    uid: email
    state: absent
"""

RETURN = """
contact_point:
  description: Contact point created or updated by the module.
  returned: success
  type: complex
  contains:
    uid:
      description: The uid of the contact point.
      returned: success
      type: str
      sample:
        - ddmyrs0f74t8hc
    name:
      description: The name of the contact point.
      returned: success
      type: str
      sample:
        - supportmail
    type:
      description: The type of the contact point.
      returned: success
      type: str
      sample:
        - email
    disableResolveMessage:
      description: Is the resolve message of the contact point disabled.
      returned: success
      type: bool
      sample:
        - false
    settings:
      description: The type specific settings of the contact point.
      returned: success
      type: dict
      sample:
        - addresses: "support@example.com"
          singleEmail: false
    secureFields:
      description: The secure fields config of the contact point.
      returned: success
      type: dict
diff:
  description: Difference between previous and updated contact point.
  returned: changed
  type: complex
  contains:
    before:
      description: Previous contact point.
      returned: changed
      type: dict
      sample:
        - uid: ddmyrs0f74t8hc
          name: supportmail
          type: email
          disableResolveMessage: false
          settings:
            addresses: support@example.com
            singleEmail: false
          secureFields: {}
    after:
      description: Current contact point.
      returned: changed
      type: dict
      sample:
        - uid: ddmyrs0f74t8hc
          name: supportmail
          type: email
          disableResolveMessage: true
          settings:
            addresses: support123@example.com
            singleEmail: false
          secureFields: {}
"""

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_text
from ansible_collections.community.grafana.plugins.module_utils.base import (
    grafana_argument_spec,
    clean_url,
)
from ansible.module_utils.urls import basic_auth_header


class GrafanaAPIException(Exception):
    pass


def grafana_contact_point_payload(data):
    payload = {
        "uid": data["uid"],
        "name": data["name"],
        "type": data["type"],
        "disableResolveMessage": data["disable_resolve_message"],
        "settings": {},
    }

    if data["type"] == "alertmanager":
        payload["type"] = "prometheus-alertmanager"

    type_settings_map = {
        "alertmanager": {
            "basicAuthPassword": "alertmanager_password",
            "url": "alertmanager_url",
            "basicAuthUser": "alertmanager_username",
        },
        "dingding": {
            "message": "dingding_message",
            "msgType": "dingding_message_type",
            "title": "dingding_title",
            "url": "dingding_url",
        },
        "discord": {
            "avatar_url": "discord_avatar_url",
            "message": "discord_message",
            "title": "discord_title",
            "url": "discord_url",
            "use_discord_username": "discord_use_username",
        },
        "email": {
            "addresses": "email_addresses",
            "message": "email_message",
            "singleEmail": "email_single",
            "subject": "email_subject",
        },
        "googlechat": {
            "url": "googlechat_url",
            "message": "googlechat_message",
            "title": "googlechat_title",
        },
        "kafka": {
            "apiVersion": "kafka_api_version",
            "kafkaClusterId": "kafka_cluster_id",
            "description": "kafka_description",
            "details": "kafka_details",
            "password": "kafka_password",
            "kafkaRestProxy": "kafka_rest_proxy_url",
            "kafkaTopic": "kafka_topic",
            "username": "kafka_username",
        },
        "line": {
            "description": "line_description",
            "title": "line_title",
            "token": "line_token",
        },
        "opsgenie": {
            "apiKey": "opsgenie_api_key",
            "autoClose": "opsgenie_auto_close",
            "description": "opsgenie_description",
            "message": "opsgenie_message",
            "overridePriority": "opsgenie_override_priority",
            "responders": "opsgenie_responders",
            "sendTagsAs": "opsgenie_send_tags_as",
            "apiUrl": "opsgenie_url",
        },
        "pagerduty": {
            "class": "pagerduty_class",
            "client": "pagerduty_client",
            "client_url": "pagerduty_client_url",
            "component": "pagerduty_component",
            "details": "pagerduty_details",
            "group": "pagerduty_group",
            "integrationKey": "pagerduty_integration_key",
            "severity": "pagerduty_severity",
            "source": "pagerduty_source",
            "summary": "pagerduty_summary",
        },
        "pushover": {
            "apiToken": "pushover_api_token",
            "device": "pushover_devices",
            "expire": "pushover_expire",
            "message": "pushover_message",
            "okPriority": "pushover_ok_priority",
            "okSound": "pushover_ok_sound",
            "priority": "pushover_priority",
            "retry": "pushover_retry",
            "sound": "pushover_sound",
            "title": "pushover_title",
            "uploadImage": "pushover_upload_image",
            "userKey": "pushover_user_key",
        },
        "sensugo": {
            "apiKey": "sensugo_api_key",
            "url": "sensugo_url",
            "check": "sensugo_check",
            "entity": "sensugo_entity",
            "handler": "sensugo_handler",
            "message": "sensugo_message",
            "namespace": "sensugo_namespace",
        },
        "slack": {
            "endpointUrl": "slack_endpoint_url",
            "icon_emoji": "slack_icon_emoji",
            "icon_url": "slack_icon_url",
            "mentionChannel": "slack_mention_channel",
            "mentionGroups": "slack_mention_groups",
            "mentionUsers": "slack_mention_users",
            "recipient": "slack_recipient",
            "text": "slack_text",
            "title": "slack_title",
            "token": "slack_token",
            "url": "slack_url",
            "username": "slack_username",
        },
        "teams": {
            "message": "teams_message",
            "sectiontitle": "teams_section_title",
            "title": "teams_title",
            "url": "teams_url",
        },
        "telegram": {
            "chatid": "telegram_chat_id",
            "disable_notification": "telegram_disable_notifications",
            "message": "telegram_message",
            "parse_mode": "telegram_parse_mode",
            "protect_content": "telegram_protect_content",
            "bottoken": "telegram_token",
            "disable_web_page_preview": "telegram_web_page_view",
        },
        "threema": {
            "api_secret": "threema_api_secret",
            "description": "threema_description",
            "gateway_id": "threema_gateway_id",
            "recipient_id": "threema_recipient_id",
            "title": "threema_title",
        },
        "victorops": {
            "description": "victorops_description",
            "messageType": "victorops_message_type",
            "title": "victorops_title",
            "url": "victorops_url",
        },
        "webex": {
            "api_url": "webex_api_url",
            "message": "webex_message",
            "room_id": "webex_room_id",
            "bot_token": "webex_token",
        },
        "webhook": {
            "authorization_credentials": "webhook_authorization_credentials",
            "authorization_scheme": "webhook_authorization_scheme",
            "httpMethod": "webhook_http_method",
            "maxAlerts": "webhook_max_alerts",
            "message": "webhook_message",
            "password": "webhook_password",
            "title": "webhook_title",
            "url": "webhook_url",
            "username": "webhook_username",
        },
        "wecom": {
            "agent_id": "wecom_agent_id",
            "corp_id": "wecom_corp_id",
            "message": "wecom_message",
            "msgtype": "wecom_msg_type",
            "secret": "wecom_secret",
            "title": "wecom_title",
            "touser": "wecom_to_user",
            "url": "wecom_url",
        },
    }

    type_settings = type_settings_map.get(data["type"])
    if type_settings:
        for setting_key, data_key in type_settings.items():
            if data[data_key] is not None:
                if data_key == "pushover_priority":
                    payload["settings"][setting_key] = {
                        "emergency": "2",
                        "high": "1",
                        "normal": "0",
                        "low": "-1",
                        "lowest": "-2",
                    }[data[data_key]]
                elif data_key == "dingding_message_type":
                    payload["settings"][setting_key] = {
                        "link": "link",
                        "action_card": "actionCard",
                    }[data[data_key]]
                elif data_key in ["email_addresses", "pushover_devices"]:
                    payload["settings"][setting_key] = ";".join(data[data_key])
                elif data_key in ["slack_mention_users", "slack_mention_groups"]:
                    payload["settings"][setting_key] = ",".join(data[data_key])
                elif data.get(data_key):
                    payload["settings"][setting_key] = data[data_key]

    return payload


class GrafanaContactPointInterface(object):
    def __init__(self, module):
        self._module = module
        self.org_id = None
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
            self.org_id = (
                self.grafana_organization_by_name(
                    module.params, module.params["org_name"]
                )
                if module.params["org_name"]
                else module.params["org_id"]
            )
            self.grafana_switch_organisation(module.params, self.org_id)
        # }}}
        self.contact_point = self.grafana_check_contact_point_match(module.params)

    def grafana_handle_api_provisioning(self, data):
        if not self.contact_point or (
            not self.contact_point.get("provenance") and not data.get("provisioning")
        ):
            self.headers["X-Disable-Provenance"] = "true"
        elif self.contact_point.get("provenance") and not data.get("provisioning"):
            self._module.fail_json(
                msg="Unable to update contact point '%s': provisioning cannot be disabled if it's already enabled"
                % data["uid"]
            )
        else:
            pass

    def grafana_organization_by_name(self, data, org_name):
        r, info = fetch_url(
            self._module,
            "%s/api/user/orgs" % data["url"],
            headers=self.headers,
            method="GET",
        )
        organizations = json.loads(to_text(r.read()))
        orga = next((org for org in organizations if org["name"] == org_name))
        if orga:
            return orga["orgId"]

        raise GrafanaAPIException(
            "Current user isn't member of organization: %s" % org_name
        )

    def grafana_switch_organisation(self, data, org_id):
        r, info = fetch_url(
            self._module,
            "%s/api/user/using/%s" % (data["url"], org_id),
            headers=self.headers,
            method="POST",
        )
        if info["status"] != 200:
            raise GrafanaAPIException(
                "Unable to switch to organization '%s': %s" % (org_id, info)
            )

    def grafana_check_contact_point_match(self, data):
        r, info = fetch_url(
            self._module,
            "%s/api/v1/provisioning/contact-points" % data["url"],
            headers=self.headers,
            method="GET",
        )

        if info["status"] == 200:
            contact_points = json.loads(to_text(r.read()))
            contact_point = next(
                (cp for cp in contact_points if cp["uid"] == data["uid"]), None
            )
            return contact_point
        elif info["status"] == 404:
            self._module.fail_json(
                msg="Unable to get contact point: API endpoint not found - please check your Grafana version"
            )
        else:
            raise GrafanaAPIException(
                "Unable to get contact point '%s': %s" % (data["uid"], info)
            )

    def grafana_handle_contact_point(self, data):
        payload = grafana_contact_point_payload(data)

        if data["state"] == "present":
            self.grafana_handle_api_provisioning(data)
            if self.contact_point:
                return self.grafana_update_contact_point(data, payload)
            else:
                return self.grafana_create_contact_point(data, payload)
        else:
            if self.contact_point:
                return self.grafana_delete_contact_point(data)
            else:
                return {"changed": False, "state": data["state"]}

    def grafana_create_contact_point(self, data, payload):
        r, info = fetch_url(
            self._module,
            "%s/api/v1/provisioning/contact-points" % data["url"],
            data=json.dumps(payload),
            headers=self.headers,
            method="POST",
        )

        if info["status"] == 202:
            contact_point = json.loads(to_text(r.read()))
            return {
                "changed": True,
                "contact_point": contact_point,
                "state": data["state"],
            }
        else:
            raise GrafanaAPIException("Unable to create contact point: %s" % info)

    def grafana_update_contact_point(self, data, payload):
        r, info = fetch_url(
            self._module,
            "%s/api/v1/provisioning/contact-points/%s" % (data["url"], data["uid"]),
            data=json.dumps(payload),
            headers=self.headers,
            method="PUT",
        )

        if info["status"] == 202:
            contact_point = self.grafana_check_contact_point_match(data)

            if contact_point.get("provenance") and data.get("provisioning"):
                del contact_point["provenance"]

            if self.contact_point == contact_point:
                return {
                    "changed": False,
                    "contact_point": contact_point,
                    "state": data["state"],
                }
            else:
                return {
                    "changed": True,
                    "diff": {"before": self.contact_point, "after": contact_point},
                    "contact_point": contact_point,
                    "state": data["state"],
                }
        else:
            raise GrafanaAPIException(
                "Unable to update contact point '%s': %s" % (data["uid"], info)
            )

    def grafana_delete_contact_point(self, data):
        r, info = fetch_url(
            self._module,
            "%s/api/v1/provisioning/contact-points/%s" % (data["url"], data["uid"]),
            headers=self.headers,
            method="DELETE",
        )

        if info["status"] == 202:
            return {
                "changed": True,
                "contact_point": self.contact_point,
                "state": data["state"],
            }
        elif info["status"] == 404:
            return {"changed": False, "state": data["state"]}
        else:
            raise GrafanaAPIException(
                "Unable to delete contact point '%s': %s" % (data["uid"], info)
            )


def main():
    argument_spec = grafana_argument_spec()
    argument_spec.update(
        # general arguments
        disable_resolve_message=dict(type="bool", default=False),
        include_image=dict(type="bool", default=False),
        name=dict(type="str"),
        org_id=dict(type="int", default=1),
        org_name=dict(type="str"),
        provisioning=dict(type="bool", default=True),
        type=dict(
            type="str",
            choices=[
                "alertmanager",
                "dingding",
                "discord",
                "email",
                "googlechat",
                "kafka",
                "line",
                "opsgenie",
                "pagerduty",
                "pushover",
                "sensugo",
                "slack",
                "teams",
                "telegram",
                "threema",
                "victorops",
                "webex",
                "webhook",
                "wecom",
            ],
        ),
        uid=dict(required=True, type="str"),
        # alertmanager
        alertmanager_password=dict(type="str", no_log=True),
        alertmanager_url=dict(type="str"),
        alertmanager_username=dict(type="str"),
        # dingding
        dingding_message=dict(type="str"),
        dingding_message_type=dict(type="str"),
        dingding_title=dict(type="str"),
        dingding_url=dict(type="str"),
        # discord
        discord_avatar_url=dict(type="str"),
        discord_message=dict(type="str"),
        discord_title=dict(type="str"),
        discord_url=dict(type="str", no_log=True),
        discord_use_username=dict(type="bool", default=False),
        # email
        email_addresses=dict(type="list", elements="str"),
        email_message=dict(type="str"),
        email_single=dict(type="bool", default=False),
        email_subject=dict(type="str"),
        # googlechat
        googlechat_url=dict(type="str", no_log=True),
        googlechat_message=dict(type="str"),
        googlechat_title=dict(type="str"),
        # kafka
        kafka_api_version=dict(type="str", default="v2"),
        kafka_cluster_id=dict(type="str"),
        kafka_description=dict(type="str"),
        kafka_details=dict(type="str"),
        kafka_password=dict(type="str", no_log=True),
        kafka_rest_proxy_url=dict(type="str", no_log=True),
        kafka_topic=dict(type="str"),
        kafka_username=dict(type="str"),
        # line
        line_description=dict(type="str"),
        line_title=dict(type="str"),
        line_token=dict(type="str", no_log=True),
        # opsgenie
        opsgenie_api_key=dict(type="str", no_log=True),
        opsgenie_auto_close=dict(type="bool"),
        opsgenie_description=dict(type="str"),
        opsgenie_message=dict(type="str"),
        opsgenie_override_priority=dict(type="bool"),
        opsgenie_responders=dict(type="list", elements="dict"),
        opsgenie_send_tags_as=dict(type="str"),
        opsgenie_url=dict(type="str"),
        # pagerduty
        pagerduty_class=dict(type="str"),
        pagerduty_client=dict(type="str"),
        pagerduty_client_url=dict(type="str"),
        pagerduty_component=dict(type="str"),
        pagerduty_details=dict(type="list", elements="dict"),
        pagerduty_group=dict(type="str"),
        pagerduty_integration_key=dict(type="str", no_log=True),
        pagerduty_severity=dict(
            type="str", choices=["critical", "error", "warning", "info"]
        ),
        pagerduty_source=dict(type="str"),
        pagerduty_summary=dict(type="str"),
        # pushover
        pushover_api_token=dict(type="str", no_log=True),
        pushover_devices=dict(type="list", elements="str"),
        pushover_expire=dict(type="int"),
        pushover_message=dict(type="str"),
        pushover_ok_priority=dict(type="int"),
        pushover_ok_sound=dict(type="str"),
        pushover_priority=dict(type="int"),
        pushover_retry=dict(type="int"),
        pushover_sound=dict(type="str"),
        pushover_title=dict(type="str"),
        pushover_upload_image=dict(type="bool", default=True),
        pushover_user_key=dict(type="str", no_log=True),
        # sensugo
        sensugo_api_key=dict(type="str", no_log=True),
        sensugo_url=dict(type="str"),
        sensugo_check=dict(type="str"),
        sensugo_entity=dict(type="str"),
        sensugo_handler=dict(type="str"),
        sensugo_message=dict(type="str"),
        sensugo_namespace=dict(type="str"),
        # slack
        slack_endpoint_url=dict(type="str"),
        slack_icon_emoji=dict(type="str"),
        slack_icon_url=dict(type="str"),
        slack_mention_channel=dict(type="str", choices=["here", "channel"]),
        slack_mention_groups=dict(type="list", elements="str"),
        slack_mention_users=dict(type="list", elements="str"),
        slack_recipient=dict(type="str"),
        slack_text=dict(type="str"),
        slack_title=dict(type="str"),
        slack_token=dict(type="str", no_log=True),
        slack_url=dict(type="str", no_log=True),
        slack_username=dict(type="str"),
        # teams
        teams_message=dict(type="str"),
        teams_section_title=dict(type="str"),
        teams_title=dict(type="str"),
        teams_url=dict(type="str", no_log=True),
        # telegram
        telegram_chat_id=dict(type="str"),
        telegram_disable_notifications=dict(type="bool"),
        telegram_message=dict(type="str"),
        telegram_parse_mode=dict(type="str"),
        telegram_protect_content=dict(type="bool"),
        telegram_token=dict(type="str", no_log=True),
        telegram_web_page_view=dict(type="bool"),
        # threema
        threema_api_secret=dict(type="str", no_log=True),
        threema_description=dict(type="str"),
        threema_gateway_id=dict(type="str"),
        threema_recipient_id=dict(type="str"),
        threema_title=dict(type="str"),
        # victorops
        victorops_description=dict(type="str"),
        victorops_message_type=dict(type="str", choices=["CRITICAL", "RECOVERY"]),
        victorops_title=dict(type="str"),
        victorops_url=dict(type="str"),
        # webex
        webex_api_url=dict(type="str"),
        webex_message=dict(type="str"),
        webex_room_id=dict(type="str"),
        webex_token=dict(type="str", no_log=True),
        # webhook
        webhook_authorization_credentials=dict(type="str", no_log=True),
        webhook_authorization_scheme=dict(type="str"),
        webhook_http_method=dict(type="str", choices=["POST", "PUT"]),
        webhook_max_alerts=dict(type="int"),
        webhook_message=dict(type="str"),
        webhook_password=dict(type="str", no_log=True),
        webhook_title=dict(type="str"),
        webhook_url=dict(type="str"),
        webhook_username=dict(type="str"),
        # wecom
        wecom_agent_id=dict(type="str"),
        wecom_corp_id=dict(type="str"),
        wecom_message=dict(type="str"),
        wecom_msg_type=dict(type="str"),
        wecom_secret=dict(type="str", no_log=True),
        wecom_title=dict(type="str"),
        wecom_to_user=dict(type="list", elements="str"),
        wecom_url=dict(type="str", no_log=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=[["url_username", "url_password", "org_id"]],
        mutually_exclusive=[["url_username", "grafana_api_key"]],
        required_if=[
            ["state", "present", ["name", "type"]],
            ["type", "alertmanager", ["alertmanager_url"]],
            ["type", "dingding", ["dingding_url"]],
            ["type", "discord", ["discord_url"]],
            ["type", "email", ["email_addresses"]],
            ["type", "googlechat", ["googlechat_url"]],
            ["type", "kafka", ["kafka_rest_proxy_url", "kafka_topic"]],
            ["type", "line", ["line_token"]],
            ["type", "opsgenie", ["opsgenie_api_key", "opsgenie_url"]],
            ["type", "pagerduty", ["pagerduty_integration_key"]],
            ["type", "pushover", ["pushover_api_token", "pushover_user_key"]],
            ["type", "sensugo", ["sensugo_api_key", "sensugo_url"]],
            ["type", "slack", ["slack_recipient", "slack_token", "slack_url"]],
            ["type", "teams", ["teams_url"]],
            ["type", "telegram", ["telegram_chat_id", "telegram_token"]],
            [
                "type",
                "threema",
                ["threema_api_secret", "threema_gateway_id", "threema_recipient_id"],
            ],
            ["type", "victorops", ["victorops_url"]],
            ["type", "webex", ["webex_token", "webex_room_id"]],
            ["type", "webhook", ["webhook_url"]],
            [
                "type",
                "wecom",
                ["wecom_url", "wecom_agent_id", "wecom_corp_id", "wecom_secret"],
            ],
        ],
    )

    module.params["url"] = clean_url(module.params["url"])
    grafana_iface = GrafanaContactPointInterface(module)

    result = grafana_iface.grafana_handle_contact_point(module.params)
    module.exit_json(failed=False, **result)


if __name__ == "__main__":
    main()
# TODO: check api messages
