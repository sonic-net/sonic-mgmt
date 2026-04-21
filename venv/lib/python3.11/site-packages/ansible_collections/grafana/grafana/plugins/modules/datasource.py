#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Ishan Jain (@ishanjainn)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

DOCUMENTATION = '''
---
module: datasource
author:
  - Ishan Jain (@ishanjainn)
version_added: "0.0.1"
short_description: Manage Data sources in Grafana
description:
  - Create, Update and delete Data sources using Ansible.
requirements: [ "requests >= 1.0.0" ]
notes:
  - Does not support C(check_mode).
  - Does not support C(Idempotency).
options:
  dataSource:
    description:
      - JSON source code for the Data source.
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
      - State for the Grafana Datasource.
    choices: [ present, absent ]
    default: present
    type: str
'''

EXAMPLES = '''
- name: Create/Update Data sources
  grafana.grafana.datasource:
    dataSource:
      name: Prometheus
      type: prometheus
      access: proxy
      url: http://localhost:9090
      jsonData:
        httpMethod: POST
        manageAlerts: true
        prometheusType: Prometheus
        cacheLevel: High
    grafana_url: "{{ grafana_url }}"
    grafana_api_key: "{{ grafana_api_key }}"
    state: present

- name: Delete Data sources
  grafana.grafana.datasource:
    dataSource: "{{ lookup('ansible.builtin.file', 'datasource.json') | to_yaml }}"
    grafana_url: "{{ grafana_url }}"
    grafana_api_key: "{{ grafana_api_key }}"
    state: absent
'''

RETURN = r'''
output:
  description: Dict object containing Data source information.
  returned: On success
  type: dict
  contains:
    datasource:
      description: The response body content for the data source configuration.
      returned: state is present and on success
      type: dict
      sample: {
                "access": "proxy",
                "basicAuth": false,
                "basicAuthUser": "",
                "database": "db-name",
                "id": 20,
                "isDefault": false,
                "jsonData": {},
                "name": "ansible-integration",
                "orgId": 1,
                "readOnly": false,
                "secureJsonFields": {
                    "password": true
                },
                "type": "influxdb",
                "typeLogoUrl": "",
                "uid": "ansibletest",
                "url": "https://grafana.github.com/grafana-ansible-collection",
                "user": "user",
                "version": 1,
                "withCredentials": false
            }
    id:
      description: The ID assigned to the data source.
      returned: on success
      type: int
      sample: 20
    name:
      description: The name of the data source defined in the JSON source code.
      returned: state is present and on success
      type: str
      sample: "ansible-integration"
    message:
      description: The message returned after the operation on the Data source.
      returned: on success
      type: str
      sample: "Datasource added"
'''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

__metaclass__ = type


def present_datasource(module):
    if module.params['grafana_url'][-1] == '/':
        module.params['grafana_url'] = module.params['grafana_url'][:-1]

    api_url = module.params['grafana_url'] + '/api/datasources'

    headers = {
        "Authorization": 'Bearer ' + module.params['grafana_api_key'],
        'User-Agent': 'grafana-ansible-collection',
    }
    result = requests.post(api_url, json=module.params['dataSource'], headers=headers)

    if result.status_code == 200:
        return False, True, result.json()
    elif result.status_code == 409:
        get_id_url = requests.get(module.params['grafana_url'] + '/api/datasources/id/' + module.params['dataSource']['name'],
                                  headers=headers)

        api_url = module.params['grafana_url'] + '/api/datasources/' + str(get_id_url.json()['id'])

        result = requests.put(api_url, json=module.params['dataSource'], headers=headers)

        if result.status_code == 200:
            return False, True, result.json()
        else:
            return True, False, {"status": result.status_code, 'response': result.json()['message']}

    else:
        return True, False, {"status": result.status_code, 'response': result.json()['message']}


def absent_datasource(module):
    if module.params['grafana_url'][-1] == '/':
        module.params['grafana_url'] = module.params['grafana_url'][:-1]

    api_url = module.params['grafana_url'] + '/api/datasources/name/' + module.params['dataSource']['name']

    result = requests.delete(api_url, headers={
        "Authorization": 'Bearer ' + module.params['grafana_api_key'],
        'User-Agent': 'grafana-ansible-collection',
    })

    if result.status_code == 200:
        return False, True, {"status": result.status_code, 'response': result.json()['message']}
    else:
        return True, False, {"status": result.status_code, 'response': result.json()['message']}


def main():

    module_args = dict(
        dataSource=dict(type='dict', required=True),
        grafana_url=dict(type='str', required=True),
        grafana_api_key=dict(type='str', required=True, no_log=True),
        state=dict(type='str', required=False, default='present', choices=['present', 'absent'])
    )

    choice_map = {
        "present": present_datasource,
        "absent": absent_datasource,
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
