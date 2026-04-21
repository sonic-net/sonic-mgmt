<!-- BEGIN_ANSIBLE_DOCS -->
# Ansible Role: telekom_mms.icinga_director.ansible_icinga
---
Version: 1.35.0

This role is used to configure an Icinga Instance over its Icinga Director.

Tags: icinga

## Requirements
---
| Platform | Versions |
| -------- | -------- |
| all |  |

## Supported Operating Systems
- all

## Role Variables

- `icinga_command_templates`:
  - Default: ``
  - Description: A list of Icinga command_templat to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `command`:
      - description:

        - "The command Icinga should run."

        - "Absolute paths are accepted as provided, relative paths are prefixed with "PluginDir + ", similar Constant prefixes are allowed."

        - "Spaces will lead to separation of command path and standalone arguments."

        - "Please note that this means that we do not support spaces in plugin names and paths right now."

      - default: ""
      - type: "str"
      - required: "no"

    - `command_type`:
      - description:

        - "Plugin Check commands are what you need when running checks against your infrastructure."

        - "Notification commands will be used when it comes to notify your users."

        - "Event commands allow you to trigger specific actions when problems occur."

        - "Some people use them for auto-healing mechanisms, like restarting services or rebooting systems at specific thresholds."

      - Choices:
          - PluginCheck
          - PluginNotification
          - PluginEvent
      - default: "PluginCheck"
      - type: "str"
      - required: "no"

    - `disabled`:
      - description:

        - "Disabled objects will not be deployed."

      - Choices:
          - True
          - False
      - default: "False"
      - type: "bool"
      - required: "no"

    - `name`:
      - description:

        - "Name of the command template."

      - default: ""
      - type: "str"
      - required: "yes"

    - `imports`:
      - description:

        - "Importable templates, add as many as you want. Please note that order matters when importing properties from multiple templates - last one wins."

      - default: ""
      - type: "list"
      - required: "no"

    - `timeout`:
      - description:

        - "Optional command timeout. Allowed values are seconds or durations postfixed with a specific unit (for example 1m or also 3m 30s)."

      - default: ""
      - type: "str"
      - required: "no"

    - `zone`:
      - description:

        - "Icinga cluster zone. Allows to manually override Directors decisions of where to deploy your config to."

        - "You should consider not doing so unless you gained deep understanding of how an Icinga Cluster stack works."

      - default: ""
      - type: "str"
      - required: "no"

    - `vars`:
      - description:

        - "Custom properties of the command template."

      - default: ""
      - type: "dict"
      - required: "no"

    - `arguments`:
      - description:

        - "Arguments of the command template."

      - default: ""
      - type: "dict"
      - required: "no"

- `icinga_commands`:
  - Default: ``
  - Description: A list of Icinga commands to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `command`:
      - description:

        - "The command Icinga should run. Required when state is C(present)."

        - "Absolute paths are accepted as provided, relative paths are prefixed with "PluginDir + ", similar Constant prefixes are allowed."

        - "Spaces will lead to separation of command path and standalone arguments."

        - "Please note that this means that we do not support spaces in plugin names and paths right now."

      - default: ""
      - type: "str"
      - required: "no"

    - `command_type`:
      - description:

        - "Plugin Check commands are what you need when running checks against your infrastructure."

        - "Notification commands will be used when it comes to notify your users."

        - "Event commands allow you to trigger specific actions when problems occur."

        - "Some people use them for auto-healing mechanisms, like restarting services or rebooting systems at specific thresholds."

      - Choices:
          - PluginCheck
          - PluginNotification
          - PluginEvent
      - default: "PluginCheck"
      - type: "str"
      - required: "no"

    - `disabled`:
      - description:

        - "Disabled objects will not be deployed."

      - Choices:
          - True
          - False
      - default: "False"
      - type: "bool"
      - required: "no"

    - `name`:
      - description:

        - "Name of the command."

      - default: ""
      - type: "str"
      - required: "yes"

    - `imports`:
      - description:

        - "Importable templates, add as many as you want. Please note that order matters when importing properties from multiple templates - last one wins."

      - default: ""
      - type: "list"
      - required: "no"

    - `timeout`:
      - description:

        - "Optional command timeout. Allowed values are seconds or durations postfixed with a specific unit (for example 1m or also 3m 30s)."

      - default: ""
      - type: "str"
      - required: "no"

    - `zone`:
      - description:

        - "Icinga cluster zone. Allows to manually override Directors decisions of where to deploy your config to."

        - "You should consider not doing so unless you gained deep understanding of how an Icinga Cluster stack works."

      - default: ""
      - type: "str"
      - required: "no"

    - `vars`:
      - description:

        - "Custom properties of the command."

      - default: ""
      - type: "dict"
      - required: "no"

    - `arguments`:
      - description:

        - "Arguments of the command."

      - default: ""
      - type: "dict"
      - required: "no"

- `icinga_endpoints`:
  - Default: ``
  - Description: A list of Icinga endpoints to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Icinga object name for this endpoint."

        - "This is usually a fully qualified host name but it could basically be any kind of string."

        - "To make things easier for your users we strongly suggest to use meaningful names for templates."

        - "For example "generic-endpoint" is ugly, "Standard Linux Server" is easier to understand."

      - default: ""
      - type: "str"
      - required: "yes"

    - `host`:
      - description:

        - "The hostname/IP address of the remote Icinga 2 instance."

      - default: ""
      - type: "str"
      - required: "no"

    - `port`:
      - description:

        - "The service name/port of the remote Icinga 2 instance. Defaults to 5665."

      - default: ""
      - type: "int"
      - required: "no"

    - `log_duration`:
      - description:

        - "Duration for keeping replay logs on connection loss. Defaults to 1d (86400 seconds). Attribute is specified in seconds. If log_duration is set to 0, replaying logs is disabled. You could also specify the value in human readable format like 10m for 10 minutes or 1h for one hour."

      - default: ""
      - type: "str"
      - required: "no"

    - `zone`:
      - description:

        - "The name of the zone this endpoint is part of."

      - default: ""
      - type: "str"
      - required: "no"

- `icinga_host_templates`:
  - Default: ``
  - Description: A list of Icinga host_templates to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Icinga object name for this host template."

        - "This is usually a fully qualified host name but it could basically be any kind of string."

        - "To make things easier for your users we strongly suggest to use meaningful names for templates."

        - "For example "generic-host" is ugly, "Standard Linux Server" is easier to understand."

      - default: ""
      - type: "str"
      - required: "yes"

    - `display_name`:
      - description:

        - "Alternative name for this host."

        - "Might be a host alias or and kind of string helping your users to identify this host."

      - default: ""
      - type: "str"
      - required: "no"

    - `address`:
      - description:

        - "Host address. Usually an IPv4 address, but may be any kind of address your check plugin is able to deal with."

      - default: ""
      - type: "str"
      - required: "no"

    - `address6`:
      - description:

        - "Host IPv6 address. Usually an IPv64 address, but may be any kind of address your check plugin is able to deal with."

      - default: ""
      - type: "str"
      - required: "no"

    - `groups`:
      - description:

        - "Hostgroups that should be directly assigned to this node. Hostgroups can be useful for various reasons."

        - "You might assign service checks based on assigned hostgroup. They are also often used as an instrument to enforce restricted views in Icinga Web 2."

        - "Hostgroups can be directly assigned to single hosts or to host templates."

        - "You might also want to consider assigning hostgroups using apply rules."

      - default: "[]"
      - type: "list"
      - required: "no"

    - `check_command`:
      - description:

        - "The name of the check command."

        - "Though this is not required to be defined in the director, you still have to supply a check_command in a host or host-template."

      - default: ""
      - type: "str"
      - required: "no"

    - `event_command`:
      - description:

        - "Event command for host which gets called on every check execution if one of these conditions matches"

        - "The host is in a soft state"

        - "The host state changes into a hard state"

        - "The host state recovers from a soft or hard state to OK/Up"

      - default: ""
      - type: "str"
      - required: "no"

    - `check_interval`:
      - description:

        - "Your regular check interval."

      - default: ""
      - type: "str"
      - required: "no"

    - `disabled`:
      - description:

        - "Disabled objects will not be deployed."

      - Choices:
          - True
          - False
      - default: "False"
      - type: "bool"
      - required: "no"

    - `imports`:
      - description:

        - "Choose a host-template."

      - default: ""
      - type: "list"
      - required: "no"

    - `zone`:
      - description:

        - "Set the zone."

      - default: ""
      - type: "str"
      - required: "no"

    - `vars`:
      - description:

        - "Custom properties of the host."

      - default: ""
      - type: "dict"
      - required: "no"

    - `notes`:
      - description:

        - "Additional notes for this object."

      - default: ""
      - type: "str"
      - required: "no"

    - `notes_url`:
      - description:

        - "An URL pointing to additional notes for this object."

        - "Separate multiple urls like this "http://url1 http://url2""

        - "Maximum length is 255 characters."

      - default: ""
      - type: "str"
      - required: "no"

    - `has_agent`:
      - description:

        - "Whether this host has the Icinga 2 Agent installed."

      - Choices:
          - True
          - False
      - default: ""
      - type: "bool"
      - required: "no"

    - `master_should_connect`:
      - description:

        - "Whether the parent (master) node should actively try to connect to this agent."

      - Choices:
          - True
          - False
      - default: ""
      - type: "bool"
      - required: "no"

    - `accept_config`:
      - description:

        - "Whether the agent is configured to accept config."

      - Choices:
          - True
          - False
      - default: ""
      - type: "bool"
      - required: "no"

- `icinga_hostgroups`:
  - Default: ``
  - Description: A list of Icinga hostgroups to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Icinga object name for this hostgroup."

      - default: ""
      - type: "str"
      - required: "yes"

    - `display_name`:
      - description:

        - "An alternative display name for this group."

        - "If you wonder how this could be helpful just leave it blank."

      - default: ""
      - type: "str"
      - required: "no"

    - `assign_filter`:
      - description:

        - "This allows you to configure an assignment filter."

        - "Please feel free to combine as many nested operators as you want."

      - default: ""
      - type: "str"
      - required: "no"

- `icinga_hosts`:
  - Default: ``
  - Description: A list of Icinga hosts to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Icinga object name for this host."

        - "This is usually a fully qualified host name but it could basically be any kind of string."

        - "To make things easier for your users we strongly suggest to use meaningful names for templates."

        - "For example "generic-host" is ugly, "Standard Linux Server" is easier to understand."

      - default: ""
      - type: "str"
      - required: "yes"

    - `display_name`:
      - description:

        - "Alternative name for this host. Might be a host alias or and kind of string helping your users to identify this host."

      - default: ""
      - type: "str"
      - required: "no"

    - `address`:
      - description:

        - "Host address. Usually an IPv4 address, but may be any kind of address your check plugin is able to deal with."

      - default: ""
      - type: "str"
      - required: "no"

    - `address6`:
      - description:

        - "Host IPv6 address. Usually an IPv6 address, but may be any kind of address your check plugin is able to deal with."

      - default: ""
      - type: "str"
      - required: "no"

    - `groups`:
      - description:

        - "Hostgroups that should be directly assigned to this node. Hostgroups can be useful for various reasons."

        - "You might assign service checks based on assigned hostgroup. They are also often used as an instrument to enforce restricted views in Icinga Web 2."

        - "Hostgroups can be directly assigned to single hosts or to host templates."

        - "You might also want to consider assigning hostgroups using apply rules."

      - default: "[]"
      - type: "list"
      - required: "no"

    - `disabled`:
      - description:

        - "Disabled objects will not be deployed."

      - Choices:
          - True
          - False
      - default: "False"
      - type: "bool"
      - required: "no"

    - `imports`:
      - description:

        - "Choose a Host Template. Required when state is C(present)."

      - default: ""
      - type: "list"
      - required: "no"

    - `zone`:
      - description:

        - "Set the zone."

      - default: ""
      - type: "str"
      - required: "no"

    - `vars`:
      - description:

        - "Custom properties of the host."

      - default: ""
      - type: "dict"
      - required: "no"

    - `check_command`:
      - description:

        - "The name of the check command."

        - "Though this is not required to be defined in the director, you still have to supply a check_command in a host or host-template."

      - default: ""
      - type: "str"
      - required: "no"

    - `notes`:
      - description:

        - "Additional notes for this object."

      - default: ""
      - type: "str"
      - required: "no"

    - `notes_url`:
      - description:

        - "An URL pointing to additional notes for this object."

        - "Separate multiple urls like this "http://url1 http://url2""

        - "The maximum length is 255 characters."

      - default: ""
      - type: "str"
      - required: "no"

    - `has_agent`:
      - description:

        - "Whether this host has the Icinga 2 Agent installed."

      - Choices:
          - True
          - False
      - default: ""
      - type: "bool"
      - required: "no"

    - `master_should_connect`:
      - description:

        - "Whether the parent (master) node should actively try to connect to this agent."

      - Choices:
          - True
          - False
      - default: ""
      - type: "bool"
      - required: "no"

    - `accept_config`:
      - description:

        - "Whether the agent is configured to accept config."

      - Choices:
          - True
          - False
      - default: ""
      - type: "bool"
      - required: "no"

- `icinga_notifications`:
  - Default: ``
  - Description: A list of Icinga notifications to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Name of the notification."

      - default: ""
      - type: "str"
      - required: "yes"

    - `notification_interval`:
      - description:

        - "The notification interval (in seconds). This interval is used for active notifications."

        - "Defaults to 30 minutes. If set to 0, re-notifications are disabled."

      - default: ""
      - type: "str"
      - required: "no"

    - `types`:
      - description:

        - "The state transition types you want to get notifications for."

      - default: ""
      - type: "list"
      - required: "no"

    - `users`:
      - description:

        - "Users that should be notified by this notification."

      - default: ""
      - type: "list"
      - required: "no"

    - `states`:
      - description:

        - "The host or service states you want to get notifications for."

      - default: ""
      - type: "list"
      - required: "no"

    - `apply_to`:
      - description:

        - "Whether this notification should affect hosts or services."

      - Choices:
          - host
          - service
      - default: ""
      - type: "str"
      - required: "yes"

    - `assign_filter`:
      - description:

        - "The filter where the notification will take effect."

      - default: ""
      - type: "str"
      - required: "no"

    - `imports`:
      - description:

        - "Importable templates, add as many as you want. Required when state is C(present)."

        - "Please note that order matters when importing properties from multiple templates - last one wins."

      - default: ""
      - type: "list"
      - required: "no"

    - `disabled`:
      - description:

        - "Disabled objects will not be deployed."

      - Choices:
          - True
          - False
      - default: "False"
      - type: "bool"
      - required: "no"

    - `vars`:
      - description:

        - "Custom properties of the notification."

      - default: ""
      - type: "dict"
      - required: "no"

    - `time_period`:
      - description:

        - "The name of a time period which determines when this notification should be triggered."

      - default: ""
      - type: "strod"
      - required: "no"

    - `times_begin`:
      - description:

        - "First notification delay."

        - "Delay unless the first notification should be sent."

      - default: ""
      - type: "int"
      - required: "no"

    - `times_end`:
      - description:

        - "Last notification."

        - "When the last notification should be sent."

      - default: ""
      - type: "int"
      - required: "no"

    - `user_groups`:
      - description:

        - "User Groups that should be notified by this notification."

      - default: ""
      - type: "list"
      - required: "no"

- `icinga_service_applies`:
  - Default: ``
  - Description: A list of Icinga service_applies to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Name for the Icinga service apply rule."

      - default: ""
      - type: "str"
      - required: "yes"

    - `display_name`:
      - description:

        - "Alternative displayed name of the service apply rule."

      - default: ""
      - type: "str"
      - required: "no"

    - `check_command`:
      - description:

        - "Check command definition."

      - default: ""
      - type: "str"
      - required: "no"

    - `check_interval`:
      - description:

        - "Your regular check interval."

      - default: ""
      - type: "str"
      - required: "no"

    - `check_period`:
      - description:

        - "The name of a time period which determines when this object should be monitored. Not limited by default."

      - default: ""
      - type: "str"
      - required: "no"

    - `check_timeout`:
      - description:

        - "Check command timeout in seconds. Overrides the CheckCommand's timeout attribute."

      - default: ""
      - type: "str"
      - required: "no"

    - `enable_active_checks`:
      - description:

        - "Whether to actively check this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `enable_event_handler`:
      - description:

        - "Whether to enable event handlers this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `enable_notifications`:
      - description:

        - "Whether to send notifications for this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `enable_passive_checks`:
      - description:

        - "Whether to accept passive check results for this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `enable_perfdata`:
      - description:

        - "Whether to process performance data provided by this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `max_check_attempts`:
      - description:

        - "Defines after how many check attempts a new hard state is reached."

      - default: ""
      - type: "str"
      - required: "no"

    - `retry_interval`:
      - description:

        - "Retry interval, will be applied after a state change unless the next hard state is reached."

      - default: ""
      - type: "str"
      - required: "no"

    - `groups`:
      - description:

        - "Service groups that should be directly assigned to this service."

        - "Servicegroups can be useful for various reasons."

        - "They are helpful to provided service-type specific view in Icinga Web 2, either for custom dashboards or as an instrument to enforce restrictions."

        - "Service groups can be directly assigned to single services or to service templates."

      - default: ""
      - type: "list"
      - required: "no"

    - `apply_for`:
      - description:

        - "Evaluates the apply for rule for all objects with the custom attribute specified."

        - "For example selecting "host.vars.custom_attr" will generate "for (config in host.vars.array_var)" where "config" will be accessible through "$config$"."

        - "Note - only custom variables of type "Array" are eligible."

      - default: ""
      - type: "str"
      - required: "no"

    - `assign_filter`:
      - description:

        - "The filter where the service apply rule will take effect."

      - default: ""
      - type: "str"
      - required: "no"

    - `command_endpoint`:
      - description:

        - "The host where the service should be executed on."

      - default: ""
      - type: "str"
      - required: "no"

    - `imports`:
      - description:

        - "Importable templates, add as many as you want."

        - "Please note that order matters when importing properties from multiple templates - last one wins."

      - default: ""
      - type: "list"
      - required: "no"

    - `vars`:
      - description:

        - "Custom properties of the service apply rule."

      - default: ""
      - type: "dict"
      - required: "no"

    - `notes`:
      - description:

        - "Additional notes for this object."

      - default: ""
      - type: "str"
      - required: "no"

    - `notes_url`:
      - description:

        - "An URL pointing to additional notes for this object."

        - "Separate multiple urls like this "http://url1 http://url2""

        - "Maximum length is 255 characters."

      - default: ""
      - type: "str"
      - required: "no"

- `icinga_service_templates`:
  - Default: ``
  - Description: A list of Icinga service_templat to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Name of the service template."

      - default: ""
      - type: "str"
      - required: "yes"

    - `check_command`:
      - description:

        - "Check command definition."

      - default: ""
      - type: "str"
      - required: "no"

    - `check_interval`:
      - description:

        - "Your regular check interval."

      - default: ""
      - type: "str"
      - required: "no"

    - `check_period`:
      - description:

        - "The name of a time period which determines when this object should be monitored. Not limited by default."

      - default: ""
      - type: "str"
      - required: "no"

    - `check_timeout`:
      - description:

        - "Check command timeout in seconds. Overrides the CheckCommand's timeout attribute."

      - default: ""
      - type: "str"
      - required: "no"

    - `enable_active_checks`:
      - description:

        - "Whether to actively check this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `enable_event_handler`:
      - description:

        - "Whether to enable event handlers this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `enable_notifications`:
      - description:

        - "Whether to send notifications for this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `enable_passive_checks`:
      - description:

        - "Whether to accept passive check results for this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `enable_perfdata`:
      - description:

        - "Whether to process performance data provided by this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `event_command`:
      - description:

        - "Event command for service which gets called on every check execution if one of these conditions matches"

        - "The service is in a soft state"

        - "The service state changes into a hard state"

        - "The service state recovers from a soft or hard state to OK/Up"

      - default: ""
      - type: "str"
      - required: "no"

    - `groups`:
      - description:

        - "Service groups that should be directly assigned to this service."

        - "Servicegroups can be useful for various reasons."

        - "They are helpful to provided service-type specific view in Icinga Web 2, either for custom dashboards or as an instrument to enforce restrictions."

        - "Service groups can be directly assigned to single services or to service templates."

      - default: "[]"
      - type: "list"
      - required: "no"

    - `imports`:
      - description:

        - "Importable templates, add as many as you want."

        - "Please note that order matters when importing properties from multiple templates - last one wins."

      - default: "[]"
      - type: "list"
      - required: "no"

    - `max_check_attempts`:
      - description:

        - "Defines after how many check attempts a new hard state is reached."

      - default: ""
      - type: "str"
      - required: "no"

    - `notes`:
      - description:

        - "Additional notes for this object."

      - default: ""
      - type: "str"
      - required: "no"

    - `notes_url`:
      - description:

        - "An URL pointing to additional notes for this object."

        - "Separate multiple urls like this "http://url1 http://url2""

        - "Maximum length is 255 characters."

      - default: ""
      - type: "str"
      - required: "no"

    - `retry_interval`:
      - description:

        - "Retry interval, will be applied after a state change unless the next hard state is reached."

      - default: ""
      - type: "str"
      - required: "no"

    - `use_agent`:
      - description:

        - "Whether the check command for this service should be executed on the Icinga agent."

      - default: ""
      - type: "bool"
      - required: "no"

    - `vars`:
      - description:

        - "Custom properties of the service template."

      - default: "{}"
      - type: "dict"
      - required: "no"

    - `volatile`:
      - description:

        - "Whether this check is volatile."

      - default: ""
      - type: "bool"
      - required: "no"

    - `disabled`:
      - description:

        - "Disabled objects will not be deployed."

      - Choices:
          - True
          - False
      - default: "False"
      - type: "bool"
      - required: "no"

- `icinga_servicegroups`:
  - Default: ``
  - Description: A list of Icinga sservicegroups to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Name for the Icinga servicegroup."

      - default: ""
      - type: "str"
      - required: "yes"

    - `display_name`:
      - description:

        - "An alternative display name for this group."

        - "If you wonder how this could be helpful just leave it blank."

      - default: ""
      - type: "str"
      - required: "no"

    - `assign_filter`:
      - description:

        - "This allows you to configure an assignment filter."

        - "Please feel free to combine as many nested operators as you want."

      - default: ""
      - type: "str"
      - required: "no"

- `icinga_services`:
  - Default: ``
  - Description: A list of Icinga services to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Name of the service."

      - default: ""
      - type: "str"
      - required: "yes"

    - `check_command`:
      - description:

        - "Check command definition."

      - default: ""
      - type: "str"
      - required: "no"

    - `check_interval`:
      - description:

        - "Your regular check interval."

      - default: ""
      - type: "str"
      - required: "no"

    - `check_period`:
      - description:

        - "The name of a time period which determines when this object should be monitored. Not limited by default."

      - default: ""
      - type: "str"
      - required: "no"

    - `check_timeout`:
      - description:

        - "Check command timeout in seconds. Overrides the CheckCommand's timeout attribute."

      - default: ""
      - type: "str"
      - required: "no"

    - `enable_active_checks`:
      - description:

        - "Whether to actively check this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `enable_event_handler`:
      - description:

        - "Whether to enable event handlers this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `enable_notifications`:
      - description:

        - "Whether to send notifications for this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `enable_passive_checks`:
      - description:

        - "Whether to accept passive check results for this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `enable_perfdata`:
      - description:

        - "Whether to process performance data provided by this object."

      - default: ""
      - type: "bool"
      - required: "no"

    - `groups`:
      - description:

        - "Service groups that should be directly assigned to this service."

        - "Servicegroups can be useful for various reasons."

        - "They are helpful to provided service-type specific view in Icinga Web 2, either for custom dashboards or as an instrument to enforce restrictions."

        - "Service groups can be directly assigned to single services or to service templates."

      - default: "[]"
      - type: "list"
      - required: "no"

    - `host`:
      - description:

        - "Choose the host this single service should be assigned to."

      - default: ""
      - type: "str"
      - required: "yes"

    - `imports`:
      - description:

        - "Importable templates, add as many as you want."

        - "Please note that order matters when importing properties from multiple templates - last one wins."

      - default: "[]"
      - type: "list"
      - required: "no"

    - `max_check_attempts`:
      - description:

        - "Defines after how many check attempts a new hard state is reached."

      - default: ""
      - type: "str"
      - required: "no"

    - `notes`:
      - description:

        - "Additional notes for this object."

      - default: ""
      - type: "str"
      - required: "no"

    - `notes_url`:
      - description:

        - "An URL pointing to additional notes for this object."

        - "Separate multiple urls like this "http://url1 http://url2""

        - "Maximum length is 255 characters."

      - default: ""
      - type: "str"
      - required: "no"

    - `retry_interval`:
      - description:

        - "Retry interval, will be applied after a state change unless the next hard state is reached."

      - default: ""
      - type: "str"
      - required: "no"

    - `use_agent`:
      - description:

        - "Whether the check command for this service should be executed on the Icinga agent."

      - default: ""
      - type: "bool"
      - required: "no"

    - `vars`:
      - description:

        - "Custom properties of the service."

      - default: "{}"
      - type: "dict"
      - required: "no"

    - `volatile`:
      - description:

        - "Whether this check is volatile."

      - default: ""
      - type: "bool"
      - required: "no"

    - `disabled`:
      - description:

        - "Disabled objects will not be deployed."

      - Choices:
          - True
          - False
      - default: "False"
      - type: "bool"
      - required: "no"

- `icinga_timeperiods`:
  - Default: ``
  - Description: A list of Icinga timeperiods to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Name of the time period."

      - default: ""
      - type: "str"
      - required: "no"

    - `display_name`:
      - description:

        - "Alternative name for this timeperiod."

      - default: ""
      - type: "str"
      - required: "no"

    - `imports`:
      - description:

        - "Importable templates, add as many as you want."

        - "Please note that order matters when importing properties from multiple templates - last one wins."

      - default: ""
      - type: "list"
      - required: "no"

    - `ranges`:
      - description:

        - "A"

        - " "

        - "d"

        - "i"

        - "c"

        - "t"

        - " "

        - "o"

        - "f"

        - " "

        - "d"

        - "a"

        - "y"

        - "s"

        - " "

        - "a"

        - "n"

        - "d"

        - " "

        - "t"

        - "i"

        - "m"

        - "e"

        - "p"

        - "e"

        - "r"

        - "i"

        - "o"

        - "d"

        - "s"

        - "."

      - default: ""
      - type: "dict"
      - required: "no"

- `icinga_user_templates`:
  - Default: ``
  - Description: A list of Icinga user_templates to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Name of the user template."

      - default: ""
      - type: "str"
      - required: "yes"

    - `imports`:
      - description:

        - "Importable templates, add as many as you want."

        - "Please note that order matters when importing properties from multiple templates - last one wins."

      - default: ""
      - type: "list"
      - required: "no"

    - `period`:
      - description:

        - "The name of a time period which determines when notifications to this User should be triggered. Not set by default."

      - default: ""
      - type: "str"
      - required: "no"

    - `enable_notifications`:
      - description:

        - "Whether to send notifications for this user."

      - default: ""
      - type: "bool"
      - required: "no"

    - `vars`:
      - description:

        - "Custom properties of the user template."

      - default: ""
      - type: "dict"
      - required: "no"

- `icinga_users`:
  - Default: ``
  - Description: A list of Icinga users to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Name of the user."

      - default: ""
      - type: "str"
      - required: "yes"

    - `display_name`:
      - description:

        - "Alternative name for this user."

        - "In case your object name is a username, this could be the full name of the corresponding person."

      - default: ""
      - type: "str"
      - required: "no"

    - `imports`:
      - description:

        - "Importable templates, add as many as you want."

        - "Please note that order matters when importing properties from multiple templates - last one wins."

      - default: ""
      - type: "list"
      - required: "no"

    - `pager`:
      - description:

        - "The pager address of the user."

      - default: ""
      - type: "str"
      - required: "no"

    - `period`:
      - description:

        - "The name of a time period which determines when notifications to this User should be triggered. Not set by default."

      - default: ""
      - type: "str"
      - required: "no"

    - `disabled`:
      - description:

        - "Disabled objects will not be deployed."

      - Choices:
          - True
          - False
      - default: "False"
      - type: "bool"
      - required: "no"

    - `email`:
      - description:

        - "The Email address of the user."

      - default: ""
      - type: "str"
      - required: "no"

    - `groups`:
      - description:

        - "User groups that should be directly assigned to this user."

        - "Groups can be useful for various reasons. You might prefer to send notifications to groups instead of single users."

      - default: ""
      - type: "list"
      - required: "no"

    - `vars`:
      - description:

        - "Custom properties of the user."

      - default: ""
      - type: "dict"
      - required: "no"

- `icinga_zones`:
  - Default: ``
  - Description: A list of Icinga zones to configure
  - Type: list of 'str'
  - Required: no
  - Options:

    - `state`:
      - description:

        - "Apply feature state."

      - Choices:
          - present
          - absent
      - default: "present"
      - type: "str"
      - required: "no"

    - `name`:
      - description:

        - "Icinga object name for this zone."

        - "This is usually a fully qualified host name but it could basically be any kind of string."

        - "To make things easier for your users we strongly suggest to use meaningful names for templates."

        - "For example "generic-zone" is ugly, "Standard Linux Server" is easier to understand."

      - default: ""
      - type: "str"
      - required: "yes"

    - `is_global`:
      - description:

        - "Whether configuration files for this zone should be synced to all endpoints."

      - default: "False"
      - type: "bool"
      - required: "no"

    - `parent`:
      - description:

        - "The name of the parent zone."

      - default: ""
      - type: "str"
      - required: "no"

- `icinga_client_cert`:
  - Default: ``
  - Description: PEM formatted certificate chain file to be used for SSL client authentication. This file can also include the key as well, and if the key is included, `client_key' is not required.
  - Type: path
  - Required: no

- `icinga_client_key`:
  - Default: ``
  - Description: PEM formatted file that contains your private key to be used for SSL client authentication. If `client_cert' contains both the certificate and key, this option is not required.
  - Type: path
  - Required: no

- `icinga_url`:
  - Default: ``
  - Description: HTTP, HTTPS, or FTP URL in the form (http|https|ftp)://[user[:pass]]@host.domain[:port]/path
  - Type: str
  - Required: no

- `icinga_url_password`:
  - Default: ``
  - Description: The password for use in HTTP basic authentication. If the `url_username' parameter is not specified, the `url_password' parameter will not be used.
  - Type: str
  - Required: no

- `icinga_url_username`:
  - Default: ``
  - Description: The username for use in HTTP basic authentication. This parameter can be used without `url_password' for sites that allow empty passwords
  - Type: str
  - Required: no

- `icinga_use_gssapi`:
  - Default: `false`
  - Description: Use GSSAPI to perform the authentication, typically this is for Kerberos or Kerberos through Negotiate authentication. Requires the Python library gssapi <https://github.com/pythongssapi/python- gssapi> to be installed. Credentials for GSSAPI can be specified with `url_username'/`url_password' or with the GSSAPI env var `KRB5CCNAME' that specified a custom Kerberos credential cache. NTLM authentication is `not' supported even if the GSSAPI mech for NTLM has been installed.
  - Type: bool
  - Required: no

- `icinga_use_proxy`:
  - Default: `true`
  - Description: If `no', it will not use a proxy, even if one is defined in an environment variable on the target hosts.
  - Type: bool
  - Required: no

- `icinga_validate_certs`:
  - Default: `true`
  - Description: If `no', SSL certificates will not be validated. icinga_This should only be used on personally controlled sites using selfigned certificates.
  - Type: bool
  - Required: no


## Dependencies

None.

<!-- END_ANSIBLE_DOCS -->

## Example Playbook

```bash
- hosts: all
  roles:
    - telekom_mms.icinga_director.ansible_icinga
  vars:
    icinga_url: "https://example.com"
    icinga_user: "{{ icinga_user }}"
    icinga_pass: "{{ icinga_pass }}"
    icinga_timeperiods:
      - "8x5":
        ranges:
          monday: "09:00-17:00"
          tuesday: "09:00-17:00"
          wednesday: "09:00-17:00"
          thursday: "09:00-17:00"
          friday: "09:00-17:00"
      - "24x7"
        ranges:
          monday: "00:00-24:00"
          tuesday: "00:00-24:00"
          wednesday: "00:00-24:00"
          thursday: "00:00-24:00"
          friday: "00:00-24:00"
          saturday: "00:00-24:00"
          sunday: "00:00-24:00"
    icinga_users:
      - "email_24x7"
        pager: "SIP/xxx"
        email: "foo@example.com"
      - "service_abbreviation_8x5"
        email: "foo@example.com"
    icinga_user_groups:
      - "user-group-example"
        display_name: "User Group Example"
    icinga_hostgroups:
      - "foo hosts"
    icinga_hosts:
      - "foo-bar-web01"
   icinga_scheduled_downtimes:
      - "downtime01"
```
