#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Ishan Jain (@ishanjainn)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

DOCUMENTATION = '''
---
module: dashboard
author:
  - Ishan Jain (@ishanjainn)
version_added: "0.0.1"
short_description: Manage Dashboards in Grafana
description:
  - Create, Update and delete Dashboards using Ansible.
requirements: [ "requests >= 1.0.0" ]
notes:
  - Does not support C(check_mode).
  - Does not support C(Idempotency).
options:
  dashboard:
    description:
      - JSON source code for dashboard.
    type: dict
    required: true
  grafana_url:
    description:
      - URL of the Grafana instance.
    type: str
    required: true
  grafana_api_key:
    description:
      - Grafana API Key to authenticate with Grafana Cloud.
    type: str
    required : true
  state:
    description:
      - State for the Grafana Dashboard.
    choices: [ present, absent ]
    default: present
    type: str
'''

EXAMPLES = '''
- name: Create/Update a dashboard
  grafana.grafana.dashboard:
    dashboard: "{{ lookup('ansible.builtin.file', 'dashboard.json') }}"
    grafana_url: "{{ grafana_url }}"
    grafana_api_key: "{{ grafana_api_key }}"
    state: present

- name: Delete dashboard
  grafana.grafana.dashboard:
    dashboard: "{{ lookup('ansible.builtin.file', 'dashboard.json') }}"
    grafana_url: "{{ grafana_url }}"
    grafana_api_key: "{{ grafana_api_key }}"
    state: absent
'''

RETURN = r'''
output:
  description: Dict object containing folder information.
  returned: On success
  type: dict
  contains:
    id:
      description: The ID for the dashboard.
      returned: on success
      type: int
      sample: 17
    slug:
      description: The slug for the dashboard.
      returned: state is present and on success
      type: str
      sample: ansible-integration-test
    status:
      description: The status of the dashboard.
      returned: state is present and on success
      type: str
      sample: success
    uid:
      description: The UID for the dashboard.
      returned: state is present and on success
      type: str
      sample: "test1234"
    url:
      description: The endpoint for the dashboard.
      returned: state is present and on success
      type: str
      sample: "/d/test1234/ansible-integration-test"
    version:
      description: The version of the dashboard.
      returned: state is present and on success
      type: int
      sample: 2
    message:
      description: The message returned after the operation on the dashboard.
      returned: state is absent and on success
      type: str
      sample: "Dashboard Ansible Integration Test deleted"
    title:
      description: The name of the dashboard.
      returned: state is absent and on success
      type: str
      sample: "Ansible Integration Test"
'''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


__metaclass__ = type


def present_dashboard(module):

    if module.params['grafana_url'][-1] == '/':
        module.params['grafana_url'] = module.params['grafana_url'][:-1]

    api_url = module.params['grafana_url'] + '/api/dashboards/db'

    result = requests.post(api_url, json=module.params['dashboard'], headers={
        "Authorization": 'Bearer ' + module.params['grafana_api_key'],
        'User-Agent': 'grafana-ansible-collection',
    })

    if result.status_code == 200:
        return False, True, result.json()
    else:
        return True, False, {"status": result.status_code, 'response': result.json()['message']}


def absent_dashboard(module):
    if module.params['grafana_url'][-1] == '/':
        module.params['grafana_url'] = module.params['grafana_url'][:-1]

    if 'uid' not in module.params['dashboard']['dashboard']:
        return True, False, "UID is not defined in the the Dashboard configuration"

    api_url = api_url = module.params['grafana_url'] + '/api/dashboards/uid/' + module.params['dashboard']['dashboard']['uid']

    result = requests.delete(api_url, headers={
        "Authorization": 'Bearer ' + module.params['grafana_api_key'],
        'User-Agent': 'grafana-ansible-collection',
    })

    if result.status_code == 200:
        return False, True, result.json()
    else:
        return True, False, {"status": result.status_code, 'response': result.json()['message']}


def main():

    module_args = dict(
        dashboard=dict(type='dict', required=True),
        grafana_url=dict(type='str', required=True),
        grafana_api_key=dict(type='str', required=True, no_log=True),
        state=dict(type='str', required=False, default='present', choices=['present', 'absent'])
    )

    choice_map = {
        "present": present_dashboard,
        "absent": absent_dashboard,
    }

    module = AnsibleModule(
        argument_spec=module_args
    )

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib('requests'))

    is_error, has_changed, result = choice_map.get(
        module.params['state'])(module)

    if not is_error:
        module.exit_json(changed=has_changed, output=result)
    else:
        module.fail_json(msg=result)


if __name__ == '__main__':
    main()
