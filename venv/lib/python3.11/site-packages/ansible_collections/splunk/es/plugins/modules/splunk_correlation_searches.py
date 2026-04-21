#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2022 Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: splunk_correlation_searches
short_description: Splunk Enterprise Security Correlation searches resource module
description:
  - This module allows for creation, deletion, and modification of Splunk
    Enterprise Security correlation searches
  - Tested against Splunk Enterprise Server v8.2.3 with Splunk Enterprise Security v7.0.1
    installed on it.
version_added: "2.1.0"
options:
  config:
    description:
      - Configure file and directory monitoring on the system
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - Name of correlation search
        type: str
        required: true
      disabled:
        description:
          - Disable correlation search
        type: bool
        default: false
      description:
        description:
          - Description of the coorelation search, this will populate the description field for the web console
        type: str
      search:
        description:
          - SPL search string
        type: str
      app:
        description:
          - Splunk app to associate the correlation seach with
        type: str
        default: "SplunkEnterpriseSecuritySuite"
      annotations:
        description:
          - Add context from industry standard cyber security mappings in Splunk Enterprise Security
            or custom annotations
        type: dict
        suboptions:
          cis20:
            description:
              - Specify CIS20 annotations
            type: list
            elements: str
          kill_chain_phases:
            description:
              - Specify Kill 10 annotations
            type: list
            elements: str
          mitre_attack:
            description:
              - Specify MITRE ATTACK annotations
            type: list
            elements: str
          nist:
            description:
              - Specify NIST annotations
            type: list
            elements: str
          custom:
            description:
              - Specify custom framework and custom annotations
            type: list
            elements: dict
            suboptions:
              framework:
                description:
                  - Specify annotation framework
                type: str
              custom_annotations:
                description:
                  - Specify annotations associated with custom framework
                type: list
                elements: str
      ui_dispatch_context:
        description:
          - Set an app to use for links such as the drill-down search in a notable
            event or links in an email adaptive response action. If None, uses the
            Application Context.
        type: str
      time_earliest:
        description:
          - Earliest time using relative time modifiers.
        type: str
        default: "-24h"
      time_latest:
        description:
          - Latest time using relative time modifiers.
        type: str
        default: "now"
      cron_schedule:
        description:
          - Enter a cron-style schedule.
          - For example C('*/5 * * * *') (every 5 minutes) or C('0 21 * * *') (every day at 9 PM).
          - Real-time searches use a default schedule of C('*/5 * * * *').
        type: str
        default: "*/5 * * * *"
      scheduling:
        description:
          - Controls the way the scheduler computes the next execution time of a scheduled search.
          - >
            Learn more:
            https://docs.splunk.com/Documentation/Splunk/7.2.3/Report/Configurethepriorityofscheduledreports#Real-time_scheduling_and_continuous_scheduling
        type: str
        default: "realtime"
        choices:
          - "realtime"
          - "continuous"
      schedule_window:
        description:
          - Let report run at any time within a window that opens at its scheduled run time,
            to improve efficiency when there are many concurrently scheduled reports.
            The "auto" setting automatically determines the best window width for the report.
        type: str
        default: "0"
      schedule_priority:
        description:
          - Raise the scheduling priority of a report. Set to "Higher" to prioritize
            it above other searches of the same scheduling mode, or "Highest" to
            prioritize it above other searches regardless of mode. Use with discretion.
        type: str
        default: "default"
        choices:
          - "default"
          - "higher"
          - "highest"
      trigger_alert:
        description:
          - Notable response actions and risk response actions are always triggered for each result.
            Choose whether the trigger is activated once or for each result.
        type: str
        default: "once"
        choices:
          - "once"
          - "for each result"
      trigger_alert_when:
        description:
          - Raise the scheduling priority of a report. Set to "Higher" to prioritize
            it above other searches of the same scheduling mode, or "Highest" to
            prioritize it above other searches regardless of mode. Use with discretion.
        type: str
        default: "number of events"
        choices:
          - "number of events"
          - "number of results"
          - "number of hosts"
          - "number of sources"
      trigger_alert_when_condition:
        description:
          - Conditional to pass to C(trigger_alert_when)
        type: str
        default: "greater than"
        choices:
          - "greater than"
          - "less than"
          - "equal to"
          - "not equal to"
          - "drops by"
          - "rises by"
      trigger_alert_when_value:
        description:
          - Value to pass to C(trigger_alert_when)
        type: str
        default: "10"
      throttle_window_duration:
        description:
          - How much time to ignore other events that match the field values specified in Fields to group by.
        type: str
      throttle_fields_to_group_by:
        description:
          - Type the fields to consider for matching events for throttling.
        type: list
        elements: str
      suppress_alerts:
        description:
          - To suppress alerts from this correlation search or not
        type: bool
        default: false
  running_config:
    description:
      - The module, by default, will connect to the remote device and retrieve the current
        running-config to use as a base for comparing against the contents of source.
        There are times when it is not desirable to have the task get the current running-config
        for every task in a playbook.  The I(running_config) argument allows the implementer
        to pass in the configuration to use as the base config for comparison. This
        value of this option should be the output received from device by executing
        command.
    type: str
  state:
    description:
      - The state the configuration should be left in
    type: str
    choices:
      - merged
      - replaced
      - deleted
      - gathered
    default: merged

author: Ansible Security Automation Team (@pranav-bhatt) <https://github.com/ansible-security>
"""

EXAMPLES = """
# Using gathered
# --------------

- name: Gather correlation searches config
  splunk.es.splunk_correlation_searches:
    config:
      - name: Ansible Test
      - name: Ansible Test 2
    state: gathered

# RUN output:
# -----------

# "gathered": [
#     {
#       "annotations": {
#           "cis20": [
#               "test1"
#           ],
#           "custom": [
#               {
#                   "custom_annotations": [
#                       "test5"
#                   ],
#                   "framework": "test_framework"
#               }
#           ],
#           "kill_chain_phases": [
#               "test3"
#           ],
#           "mitre_attack": [
#               "test2"
#           ],
#           "nist": [
#               "test4"
#           ]
#       },
#       "app": "DA-ESS-EndpointProtection",
#       "cron_schedule": "*/5 * * * *",
#       "description": "test description",
#       "disabled": false,
#       "name": "Ansible Test",
#       "schedule_priority": "default",
#       "schedule_window": "0",
#       "scheduling": "realtime",
#       "search": '| tstats summariesonly=true values(\"Authentication.tag\") as \"tag\",dc(\"Authentication.user\") as \"user_count\",dc(\"Authent'
#                 'ication.dest\") as \"dest_count\",count from datamodel=\"Authentication\".\"Authentication\" where nodename=\"Authentication.Fai'
#                 'led_Authentication\" by \"Authentication.app\",\"Authentication.src\" | rename \"Authentication.app\" as \"app\",\"Authenticatio'
#                 'n.src\" as \"src\" | where \"count\">=6',
#       "suppress_alerts": false,
#       "throttle_fields_to_group_by": [
#           "test_field1"
#       ],
#       "throttle_window_duration": "5s",
#       "time_earliest": "-24h",
#       "time_latest": "now",
#       "trigger_alert": "once",
#       "trigger_alert_when": "number of events",
#       "trigger_alert_when_condition": "greater than",
#       "trigger_alert_when_value": "10",
#       "ui_dispatch_context": "SplunkEnterpriseSecuritySuite"
#     }
# ]

# Using merged
# ------------

- name: Merge and create new correlation searches configuration
  splunk.es.splunk_correlation_searches:
    config:
      - name: Ansible Test
        disabled: false
        description: test description
        app: DA-ESS-EndpointProtection
        annotations:
          cis20:
            - test1
          mitre_attack:
            - test2
          kill_chain_phases:
            - test3
          nist:
            - test4
          custom:
            - framework: test_framework
              custom_annotations:
                - test5
        ui_dispatch_context: SplunkEnterpriseSecuritySuite
        time_earliest: -24h
        time_latest: now
        cron_schedule: "*/5 * * * *"
        scheduling: realtime
        schedule_window: "0"
        schedule_priority: default
        trigger_alert: once
        trigger_alert_when: number of events
        trigger_alert_when_condition: greater than
        trigger_alert_when_value: "10"
        throttle_window_duration: 5s
        throttle_fields_to_group_by:
          - test_field1
        suppress_alerts: false
        search: >
                '| tstats summariesonly=true values(\"Authentication.tag\") as \"tag\",dc(\"Authentication.user\") as \"user_count\",dc(\"Authent'
                'ication.dest\") as \"dest_count\",count from datamodel=\"Authentication\".\"Authentication\" where nodename=\"Authentication.Fai'
                'led_Authentication\" by \"Authentication.app\",\"Authentication.src\" | rename \"Authentication.app\" as \"app\",\"Authenticatio'
                'n.src\" as \"src\" | where \"count\">=6'
    state: merged

# RUN output:
# -----------

# "after": [
#     {
#       "annotations": {
#           "cis20": [
#               "test1"
#           ],
#           "custom": [
#               {
#                   "custom_annotations": [
#                       "test5"
#                   ],
#                   "framework": "test_framework"
#               }
#           ],
#           "kill_chain_phases": [
#               "test3"
#           ],
#           "mitre_attack": [
#               "test2"
#           ],
#           "nist": [
#               "test4"
#           ]
#       },
#       "app": "DA-ESS-EndpointProtection",
#       "cron_schedule": "*/5 * * * *",
#       "description": "test description",
#       "disabled": false,
#       "name": "Ansible Test",
#       "schedule_priority": "default",
#       "schedule_window": "0",
#       "scheduling": "realtime",
#       "search": '| tstats summariesonly=true values(\"Authentication.tag\") as \"tag\",dc(\"Authentication.user\") as \"user_count\",dc(\"Authent'
#                 'ication.dest\") as \"dest_count\",count from datamodel=\"Authentication\".\"Authentication\" where nodename=\"Authentication.Fai'
#                 'led_Authentication\" by \"Authentication.app\",\"Authentication.src\" | rename \"Authentication.app\" as \"app\",\"Authenticatio'
#                 'n.src\" as \"src\" | where \"count\">=6',
#       "suppress_alerts": false,
#       "throttle_fields_to_group_by": [
#           "test_field1"
#       ],
#       "throttle_window_duration": "5s",
#       "time_earliest": "-24h",
#       "time_latest": "now",
#       "trigger_alert": "once",
#       "trigger_alert_when": "number of events",
#       "trigger_alert_when_condition": "greater than",
#       "trigger_alert_when_value": "10",
#       "ui_dispatch_context": "SplunkEnterpriseSecuritySuite"
#     },
# ],
# "before": [],

# Using replaced
# --------------

- name: Replace existing correlation searches configuration
  splunk.es.splunk_correlation_searches:
    state: replaced
    config:
      - name: Ansible Test
        disabled: false
        description: test description
        app: SplunkEnterpriseSecuritySuite
        annotations:
          cis20:
            - test1
            - test2
          mitre_attack:
            - test3
            - test4
          kill_chain_phases:
            - test5
            - test6
          nist:
            - test7
            - test8
          custom:
            - framework: test_framework2
              custom_annotations:
                - test9
                - test10
        ui_dispatch_context: SplunkEnterpriseSecuritySuite
        time_earliest: -24h
        time_latest: now
        cron_schedule: "*/5 * * * *"
        scheduling: continuous
        schedule_window: auto
        schedule_priority: default
        trigger_alert: once
        trigger_alert_when: number of events
        trigger_alert_when_condition: greater than
        trigger_alert_when_value: 10
        throttle_window_duration: 5s
        throttle_fields_to_group_by:
          - test_field1
          - test_field2
        suppress_alerts: true
        search: >
                '| tstats summariesonly=true values(\"Authentication.tag\") as \"tag\",dc(\"Authentication.user\") as \"user_count\",dc(\"Authent'
                'ication.dest\") as \"dest_count\",count from datamodel=\"Authentication\".\"Authentication\" where nodename=\"Authentication.Fai'
                'led_Authentication\" by \"Authentication.app\",\"Authentication.src\" | rename \"Authentication.app\" as \"app\",\"Authenticatio'
                'n.src\" as \"src\" | where \"count\">=6'

# RUN output:
# -----------

# "after": [
#     {
#         "annotations": {
#             "cis20": [
#                 "test1",
#                 "test2"
#             ],
#             "custom": [
#                 {
#                     "custom_annotations": [
#                         "test9",
#                         "test10"
#                     ],
#                     "framework": "test_framework2"
#                 }
#             ],
#             "kill_chain_phases": [
#                 "test5",
#                 "test6"
#             ],
#             "mitre_attack": [
#                 "test3",
#                 "test4"
#             ],
#             "nist": [
#                 "test7",
#                 "test8"
#             ]
#         },
#         "app": "SplunkEnterpriseSecuritySuite",
#         "cron_schedule": "*/5 * * * *",
#         "description": "test description",
#         "disabled": false,
#         "name": "Ansible Test",
#         "schedule_priority": "default",
#         "schedule_window": "auto",
#         "scheduling": "continuous",
#         "search": '| tstats summariesonly=true values(\"Authentication.tag\") as \"tag\",dc(\"Authentication.user\") as \"user_count\",dc(\"Authent'
#                   'ication.dest\") as \"dest_count\",count from datamodel=\"Authentication\".\"Authentication\" where nodename=\"Authentication.Fai'
#                   'led_Authentication\" by \"Authentication.app\",\"Authentication.src\" | rename \"Authentication.app\" as \"app\",\"Authenticatio'
#                   'n.src\" as \"src\" | where \"count\">=6',
#         "suppress_alerts": true,
#         "throttle_fields_to_group_by": [
#             "test_field1",
#             "test_field2"
#         ],
#         "throttle_window_duration": "5s",
#         "time_earliest": "-24h",
#         "time_latest": "now",
#         "trigger_alert": "once",
#         "trigger_alert_when": "number of events",
#         "trigger_alert_when_condition": "greater than",
#         "trigger_alert_when_value": "10",
#         "ui_dispatch_context": "SplunkEnterpriseSecuritySuite"
#     }
# ],
# "before": [
#     {
#         "annotations": {
#             "cis20": [
#                 "test1"
#             ],
#             "custom": [
#                 {
#                     "custom_annotations": [
#                         "test5"
#                     ],
#                     "framework": "test_framework"
#                 }
#             ],
#             "kill_chain_phases": [
#                 "test3"
#             ],
#             "mitre_attack": [
#                 "test2"
#             ],
#             "nist": [
#                 "test4"
#             ]
#         },
#         "app": "DA-ESS-EndpointProtection",
#         "cron_schedule": "*/5 * * * *",
#         "description": "test description",
#         "disabled": false,
#         "name": "Ansible Test",
#         "schedule_priority": "default",
#         "schedule_window": "0",
#         "scheduling": "realtime",
#         "search": '| tstats summariesonly=true values(\"Authentication.tag\") as \"tag\",dc(\"Authentication.user\") as \"user_count\",dc(\"Authent'
#                   'ication.dest\") as \"dest_count\",count from datamodel=\"Authentication\".\"Authentication\" where nodename=\"Authentication.Fai'
#                   'led_Authentication\" by \"Authentication.app\",\"Authentication.src\" | rename \"Authentication.app\" as \"app\",\"Authenticatio'
#                   'n.src\" as \"src\" | where \"count\">=6',
#         "suppress_alerts": false,
#         "throttle_fields_to_group_by": [
#             "test_field1"
#         ],
#         "throttle_window_duration": "5s",
#         "time_earliest": "-24h",
#         "time_latest": "now",
#         "trigger_alert": "once",
#         "trigger_alert_when": "number of events",
#         "trigger_alert_when_condition": "greater than",
#         "trigger_alert_when_value": "10",
#         "ui_dispatch_context": "SplunkEnterpriseSecuritySuite"
#     }
# ]

# Using deleted
# -------------

- name: Example to delete the corelation search
  splunk.es.splunk_correlation_searches:
    config:
      - name: Ansible Test
    state: deleted

# RUN output:
# -----------

# "after": [],
# "before": [
#     {
#       "annotations": {
#           "cis20": [
#               "test1"
#           ],
#           "custom": [
#               {
#                   "custom_annotations": [
#                       "test5"
#                   ],
#                   "framework": "test_framework"
#               }
#           ],
#           "kill_chain_phases": [
#               "test3"
#           ],
#           "mitre_attack": [
#               "test2"
#           ],
#           "nist": [
#               "test4"
#           ]
#       },
#       "app": "DA-ESS-EndpointProtection",
#       "cron_schedule": "*/5 * * * *",
#       "description": "test description",
#       "disabled": false,
#       "name": "Ansible Test",
#       "schedule_priority": "default",
#       "schedule_window": "0",
#       "scheduling": "realtime",
#       "search": '| tstats summariesonly=true values(\"Authentication.tag\") as \"tag\",dc(\"Authentication.user\") as \"user_count\",dc(\"Authent'
#                 'ication.dest\") as \"dest_count\",count from datamodel=\"Authentication\".\"Authentication\" where nodename=\"Authentication.Fai'
#                 'led_Authentication\" by \"Authentication.app\",\"Authentication.src\" | rename \"Authentication.app\" as \"app\",\"Authenticatio'
#                 'n.src\" as \"src\" | where \"count\">=6',
#       "suppress_alerts": false,
#       "throttle_fields_to_group_by": [
#           "test_field1"
#       ],
#       "throttle_window_duration": "5s",
#       "time_earliest": "-24h",
#       "time_latest": "now",
#       "trigger_alert": "once",
#       "trigger_alert_when": "number of events",
#       "trigger_alert_when_condition": "greater than",
#       "trigger_alert_when_value": "10",
#       "ui_dispatch_context": "SplunkEnterpriseSecuritySuite"
#     },
# ],
"""

RETURN = """
before:
  description: The configuration as structured data prior to module invocation.
  returned: always
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
after:
  description: The configuration as structured data after module completion.
  returned: when changed
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
gathered:
  description: Facts about the network resource gathered from the remote device as structured data.
  returned: when state is I(gathered)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
"""
