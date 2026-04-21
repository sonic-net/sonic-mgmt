# Grafana Role for Ansible Collection Community.Grafana

Configure Grafana organizations, dashboards, folders, datasources, teams and users.

## Role Variables

| Variable         | Required | Default |
| ---------------- | -------- | ------- |
| grafana_url      | yes      |
| grafana_username | yes      |
| grafana_password | yes      |
| [**grafana_users**](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_user_module.html) |
| email | no |
| is_admin | no |
| login | yes |
| name | yes |
| password | no |
| state | no |
| [**grafana_organizations**](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_organization_module.html) |
| name | yes |
| state | no |
| [**grafana_teams**](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_team_module.html) |
| email | yes |
| enforce_members | no |
| members | no |
| name | yes |
| skip_version_check | no |
| state | no |
| [**grafana_datasources**](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_datasource_module.html) |
| access | no |
| additional_json_data | no |
| additional_secure_json_data | no |
| aws_access_key | no |
| aws_assume_role_arn | no |
| aws_auth_type | no |
| aws_credentials_profile | no |
| aws_custom_metrics_namespaces | no |
| aws_default_region | no |
| aws_secret_key | no |
| azure_client | no |
| azure_cloud | no |
| azure_secret | no |
| azure_tenant | no |
| basic_auth_password | no |
| basic_auth_user | no |
| database | no |
| ds_type | no |
| ds_url | no |
| enforce_secure_data | no |
| es_version | no |
| interval | no |
| is_default | no |
| max_concurrent_shard_requests | no |
| name | yes |
| org_id | no |
| org_name | no |
| password | no |
| sslmode | no |
| state | no |
| time_field | no |
| time_interval | no |
| tls_ca_cert | no |
| tls_client_cert | no |
| tls_client_key | no |
| tls_skip_verify | no |
| trends | no |
| tsdb_resolution | no |
| tsdb_version | no |
| uid | no |
| user | no |
| with_credentials | no |
| zabbix_password | no |
| zabbix_user | no |
| [**grafana_folders**](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_folder_module.html) |
| name | yes |
| org_id | no |
| org_name | no |
| parent_uid | no |
| skip_version_check | no |
| state | no |
| uid | no |
| [**grafana_dashboards**](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_dashboard_module.html) |
| commit_message | no |
| dashboard_id | no |
| dashboard_revision | no |
| folder | no |
| org_id | no |
| org_name | no |
| overwrite | no |
| parent_folder | no |
| path | no |
| slug | no |
| state | no |
| uid | no |
| [**grafana_organization_users**](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_organization_user_module.html) |
| login | yes |
| org_id | no |
| org_name | no |
| role | no |
| state | no |
| [**grafana_notification_channel**](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_notification_channel_module.html) |
| dingding_message_type | no |
| dingding_url | no |
| disable_resolve_message | no |
| discord_message_content | no |
| discord_url | no |
| email_addresses | no |
| email_single | no |
| googlechat_url | no |
| hipchat_api_key | no |
| hipchat_room_id | no |
| hipchat_url | no |
| include_image | no |
| is_default | no |
| kafka_topic | no |
| kafka_url | no |
| line_token | no |
| name | yes |
| opsgenie_api_key | no |
| opsgenie_auto_close | no |
| opsgenie_override_priority | no |
| opsgenie_url | no |
| org_id | no |
| pagerduty_auto_resolve | no |
| pagerduty_integration_key | no |
| pagerduty_message_in_details | no |
| pagerduty_severity | no |
| prometheus_password | no |
| prometheus_url | no |
| prometheus_username | no |
| pushover_alert_sound | no |
| pushover_api_token | no |
| pushover_devices | no |
| pushover_expire | no |
| pushover_ok_sound | no |
| pushover_priority | no |
| pushover_retry | no |
| pushover_user_key | no |
| reminder_frequency | no |
| sensu_handler | no |
| sensu_password | no |
| sensu_source | no |
| sensu_url | no |
| sensu_username | no |
| slack_icon_emoji | no |
| slack_icon_url | no |
| slack_mention_channel | no |
| slack_mention_groups | no |
| slack_mention_users | no |
| slack_recipient | no |
| slack_token | no |
| slack_url | no |
| slack_username | no |
| state | no |
| teams_url | no |
| telegram_bot_token | no |
| telegram_chat_id | no |
| threema_api_secret | no |
| threema_gateway_id | no |
| threema_recipient_id | no |
| type | yes |
| uid | no |
| victorops_auto_resolve | no |
| victorops_url | no |
| webhook_http_method | no |
| webhook_password | no |
| webhook_url | no |
| webhook_username | no |
| [**grafana_silence**](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_silence_module.html) |
| comment | yes |
| created_by | yes |
| ends_at | yes |
| matchers | yes |
| org_id | no |
| org_name | no |
| starts_at | yes |
| state | no |
| [**grafana_contact_point**](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_contact_point_module.html) |
| disable_resolve_message | no |
| include_image | no |
| name | no |
| org_id | no |
| org_name | no |
| provisioning | no |
| state | no |
| type | no |
| uid | yes |
| alertmanager_password | no |
| alertmanager_url | no |
| alertmanager_username | no |
| dingding_message | no |
| dingding_message_type | no |
| dingding_title | no |
| dingding_url | no |
| discord_avatar_url | no |
| discord_message | no |
| discord_title | no |
| discord_url | no |
| discord_use_username | no |
| email_addresses | no |
| email_message | no |
| email_single | no |
| email_subject | no |
| googlechat_message | no |
| googlechat_title | no |
| googlechat_url | no |
| kafka_api_version | no |
| kafka_cluster_id | no |
| kafka_description | no |
| kafka_details | no |
| kafka_password | no |
| kafka_rest_proxy_url | no |
| kafka_topic | no |
| kafka_username | no |
| line_description | no |
| line_title | no |
| line_token | no |
| opsgenie_api_key | no |
| opsgenie_auto_close | no |
| opsgenie_description | no |
| opsgenie_message | no |
| opsgenie_override_priority | no |
| opsgenie_responders | no |
| opsgenie_send_tags_as | no |
| opsgenie_url | no |
| pagerduty_class | no |
| pagerduty_client | no |
| pagerduty_client_url | no |
| pagerduty_component | no |
| pagerduty_details | no |
| pagerduty_group | no |
| pagerduty_integration_key | no |
| pagerduty_severity | no |
| pagerduty_source | no |
| pagerduty_summary | no |
| pushover_api_token | no |
| pushover_devices | no |
| pushover_expire | no |
| pushover_message | no |
| pushover_ok_priority | no |
| pushover_ok_sound | no |
| pushover_priority | no |
| pushover_retry | no |
| pushover_sound | no |
| pushover_title | no |
| pushover_upload_image | no |
| pushover_user_key | no |
| sensugo_api_key | no |
| sensugo_check | no |
| sensugo_entity | no |
| sensugo_handler | no |
| sensugo_message | no |
| sensugo_namespace | no |
| sensugo_url | no |
| slack_endpoint_url | no |
| slack_icon_emoji | no |
| slack_icon_url | no |
| slack_mention_channel | no |
| slack_mention_groups | no |
| slack_mention_users | no |
| slack_recipient | no |
| slack_text | no |
| slack_title | no |
| slack_token | no |
| slack_url | no |
| slack_username | no |
| teams_message | no |
| teams_section_title | no |
| teams_title | no |
| teams_url | no |
| telegram_chat_id | no |
| telegram_disable_notifications | no |
| telegram_message | no |
| telegram_parse_mode | no |
| telegram_protect_content | no |
| telegram_token | no |
| telegram_web_page_view | no |
| threema_api_secret | no |
| threema_description | no |
| threema_gateway_id | no |
| threema_recipient_id | no |
| threema_title | no |
| victorops_description | no |
| victorops_message_type | no |
| victorops_title | no |
| victorops_url | no |
| webex_api_url | no |
| webex_message | no |
| webex_room_id | no |
| webex_token | no |
| webhook_authorization_credentials | no |
| webhook_authorization_scheme | no |
| webhook_http_method | no |
| webhook_max_alerts | no |
| webhook_message | no |
| webhook_password | no |
| webhook_title | no |
| webhook_url | no |
| webhook_username | no |
| wecom_agent_id | no |
| wecom_corp_id | no |
| wecom_message | no |
| wecom_msg_type | no |
| wecom_secret | no |
| wecom_title | no |
| wecom_to_user | no |
| wecom_url | no |

## Example Playbook

```yaml
---
- hosts: localhost
  gather_facts: false

  vars:
    grafana_url: "https://monitoring.example.com"
    grafana_username: "api-user"
    grafana_password: "******"

    grafana_datasources:
      - name: "Loki"
        ds_type: "loki"
        ds_url: "http://127.0.0.1:3100"
        tls_skip_verify: yes
    grafana_folders:
      - name: my_service
      - name: other_service

  roles:
    - role: community.grafana.grafana
```
