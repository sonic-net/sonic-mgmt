#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Ishan Jain (@ishanjainn)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

DOCUMENTATION = '''
---
module: alert_notification_policy
author:
  - Ishan Jain (@ishanjainn)
version_added: "0.0.1"
short_description: Manage Alerting Policies points in Grafana
description:
  - Set the notification policy tree using Ansible.
requirements: [ "requests >= 1.0.0" ]
notes:
  - Does not support C(check_mode).
options:
  Continue:
    description:
      - Continue matching subsequent sibling nodes if set to C(true).
    type: bool
    default: false
  groupByStr:
    description:
      - List of string.
      - Group alerts when you receive a notification based on labels. If empty it will be inherited from the parent policy.
    type: list
    default: []
    elements: str
  muteTimeIntervals:
    description:
      - List of string.
      - Sets the mute timing for the notfification policy.
    type: list
    default: []
    elements: str
  rootPolicyReceiver:
    description:
      - Sets the name of the contact point to be set as the default receiver.
    type: str
    default: grafana-default-email
  routes:
    description:
      - List of objects
      - Sets the Route that contains definitions of how to handle alerts.
    type: list
    required: true
    elements: dict
  groupInterval:
    description:
      - Sets the wait time to send a batch of new alerts for that group after the first notification was sent. Inherited from the parent policy if empty.
    type: str
    default: 5m
  groupWait:
    description:
      - Sets the wait time until the initial notification is sent for a new group created by an incoming alert. Inherited from the parent policy if empty.
    type: str
    default: 30s
  objectMatchers:
    description:
      - Matchers is a slice of Matchers that is sortable, implements Stringer, and provides a Matches method to match a LabelSet.
    type: list
    default: []
    elements: dict
  repeatInterval:
    description:
      - Sets the waiting time to resend an alert after they have successfully been sent.
    type: str
    default: 4h
  grafana_url:
    description:
      - URL of the Grafana instance.
    type: str
    required: true
  grafana_api_key:
    description:
      - Grafana API Key used to authenticate with Grafana.
    type: str
    required : true
'''

EXAMPLES = '''
- name: Set Notification policy tree
  grafana.grafana.alert_notification_policy:
    grafana_url: "{{ grafana_url }}"
    grafana_api_key: "{{ grafana_api_key }}"
    routes: [
      {
        receiver: myReceiver,
        object_matchers: [["env", "=", "Production"]],
      }
    ]

- name: Set nested Notification policies
  grafana.grafana.alert_notification_policy:
    routes: [
      {
        receiver: myReceiver,
        object_matchers: [["env", "=", "Production"],["team", "=", "ops"]],
        routes: [
          {
            receiver: myReceiver2,
            object_matchers: [["region", "=", "eu"]],
          }
        ]
      },
      {
        receiver: myReceiver3,
        object_matchers: [["env", "=", "Staging"]]
      }
    ]
    grafana_url: "{{ grafana_url }}"
    grafana_api_key: "{{ grafana_api_key }}"
'''

RETURN = r'''
output:
  description: Dict object containing Notification tree information.
  returned: On success
  type: dict
  contains:
    group_interval:
      description: The waiting time to send a batch of new alerts for that group after the first notification was sent. This is of the parent policy.
      returned: on success
      type: str
      sample: "5m"
    group_wait:
      description: The waiting time until the initial notification is sent for a new group created by an incoming alert. This is of the parent policy.
      returned: on success
      type: str
      sample: "30s"
    receiver:
      description: The name of the default contact point.
      returned: state is present and on success
      type: str
      sample: "grafana-default-email"
    repeat_interval:
      description: The waiting time to resend an alert after they have successfully been sent. This is of the parent policy
      returned: on success
      type: str
      sample: "4h"
    routes:
      description: The entire notification tree returned as a list.
      returned: on success
      type: list
      sample: [
                {
                    "object_matchers": [
                        [
                            "env",
                            "=",
                            "Production"
                        ]
                    ],
                    "receiver": "grafana-default-email"
                }
              ]
'''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

__metaclass__ = type


def alert_notification_policy(module):
    body = {'routes': module.params['routes'], 'Continue': module.params['Continue'],
            'groupByStr': module.params['groupByStr'], 'muteTimeIntervals': module.params['muteTimeIntervals'],
            'receiver': module.params['rootPolicyReceiver'], 'group_interval': module.params['groupInterval'],
            'group_wait': module.params['groupWait'], 'object_matchers': module.params['objectMatchers'],
            'repeat_interval': module.params['repeatInterval']}

    if module.params['grafana_url'][-1] == '/':
        module.params['grafana_url'] = module.params['grafana_url'][:-1]

    api_url = module.params['grafana_url'] + '/api/v1/provisioning/policies'
    headers = {
        'Authorization': 'Bearer ' + module.params['grafana_api_key'],
        'User-Agent': 'grafana-ansible-collection',
    }
    result = requests.get(api_url, headers=headers)

    if 'routes' not in result.json():
        api_url = module.params['grafana_url'] + '/api/v1/provisioning/policies'
        result = requests.put(api_url, json=body, headers=headers)

        if result.status_code == 202:
            return False, True, result.json()
        else:
            return True, False, {"status": result.status_code, 'response': result.json()['message']}
    elif (result.json()['receiver'] == module.params['rootPolicyReceiver'] and result.json()['routes'] == module.params['routes']
          and result.json()['group_wait'] == module.params['groupWait'] and result.json()['group_interval'] == module.params['groupInterval']
          and result.json()['repeat_interval'] == module.params['repeatInterval']):
        return False, False, result.json()
    else:
        api_url = module.params['grafana_url'] + '/api/v1/provisioning/policies'

        result = requests.put(api_url, json=body, headers=headers)

        if result.status_code == 202:
            return False, True, result.json()
        else:
            return True, False, {"status": result.status_code, 'response': result.json()['message']}


def main():

    module_args = dict(Continue=dict(type='bool', required=False, default=False),
                       groupByStr=dict(type='list', required=False, default=[], elements='str'),
                       muteTimeIntervals=dict(type='list', required=False, default=[], elements='str'),
                       rootPolicyReceiver=dict(type='str', required=False, default='grafana-default-email'),
                       routes=dict(type='list', required=True, elements='dict'),
                       groupInterval=dict(type='str', required=False, default='5m'),
                       groupWait=dict(type='str', required=False, default='30s'),
                       repeatInterval=dict(type='str', required=False, default='4h'),
                       objectMatchers=dict(type='list', required=False, default=[], elements='dict'),
                       grafana_url=dict(type='str', required=True),
                       grafana_api_key=dict(type='str', required=True, no_log=True), )

    module = AnsibleModule(argument_spec=module_args)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib('requests'))

    is_error, has_changed, result = alert_notification_policy(module)

    if not is_error:
        module.exit_json(changed=has_changed, output=result)
    else:
        module.fail_json(msg='Status code is ' + str(result['status']), output=result['response'])


if __name__ == '__main__':
    main()
