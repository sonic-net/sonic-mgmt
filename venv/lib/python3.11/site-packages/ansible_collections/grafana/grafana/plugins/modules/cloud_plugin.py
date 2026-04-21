#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Ishan Jain (@ishanjainn)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

DOCUMENTATION = '''
---
module: cloud_plugin
author:
  - Ishan Jain (@ishanjainn)
version_added: "0.0.1"
short_description: Manage Grafana Cloud Plugins
description:
  - Create, Update and delete Grafana Cloud plugins using Ansible.
requirements: [ "requests >= 1.0.0" ]
notes:
  - Does not support C(check_mode).
options:
  name:
    description:
      - Name of the plugin, e.g. grafana-github-datasource.
    type: str
    required: true
  version:
    description:
      - Version of the plugin to install.
    type: str
    default: latest
  stack_slug:
    description:
      - Name of the Grafana Cloud stack to which the plugin will be added.
    type: str
    required: true
  cloud_api_key:
    description:
      - Cloud API Key to authenticate with Grafana Cloud.
    type: str
    required : true
  state:
    description:
      - State for the Grafana Cloud Plugin.
    type: str
    default: present
    choices: [ present, absent ]
'''

EXAMPLES = '''
- name: Create/Update a plugin
  grafana.grafana.cloud_plugin:
    name: grafana-github-datasource
    version: 1.0.14
    stack_slug: "{{ stack_slug }}"
    cloud_api_key: "{{ grafana_cloud_api_key }}"
    state: present

- name: Delete a Grafana Cloud stack
  grafana.grafana.cloud_plugin:
    name: grafana-github-datasource
    stack_slug: "{{ stack_slug }}"
    cloud_api_key: "{{ grafana_cloud_api_key }}"
    state: absent
'''

RETURN = r'''
  current_version:
    description: Current version of the plugin.
    returned: On success
    type: str
    sample: "1.0.14"
  latest_version:
    description: Latest version available for the plugin.
    returned: On success
    type: str
    sample: "1.0.15"
  pluginId:
    description: Id for the Plugin.
    returned: On success
    type: int
    sample: 663
  pluginName:
    description: Name of the plugin.
    returned: On success
    type: str
    sample: "GitHub"
  pluginSlug:
    description: Slug for the Plugin.
    returned: On success
    type: str
    sample: "grafana-github-datasource"
'''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

__metaclass__ = type


def present_cloud_plugin(module):
    body = {
        'plugin': module.params['name'],
        'version': module.params['version']
    }

    api_url = 'https://grafana.com/api/instances/' + module.params['stack_slug'] + '/plugins'
    headers = {
        'Authorization': 'Bearer ' + module.params['grafana_api_key'],
        'User-Agent': 'grafana-ansible-collection',
    }

    result = requests.post(api_url, json=body, headers=headers)

    if result.status_code == 200:
        return False, True, result.json()
    elif result.status_code == 409:
        api_url = 'https://grafana.com/api/instances/' + module.params['stack_slug'] + '/plugins/' + module.params['name']
        result = requests.get(api_url, headers=headers)

        if result.json()['pluginSlug'] == module.params['name'] and result.json()['version'] == module.params['version']:
            return False, False, result.json()
        else:
            api_url = 'https://grafana.com/api/instances/' + module.params['stack_slug'] + '/plugins/' + module.params[
                'name']
            result = requests.post(api_url, json={'version': module.params['version']},
                                   headers=headers)

            return False, True, result.json()
    else:
        return True, False, {"status": result.status_code, 'response': result.json()['message']}


def absent_cloud_plugin(module):
    api_url = 'https://grafana.com/api/instances/' + module.params['stack_slug'] + '/plugins/' + module.params['name']

    result = requests.delete(api_url, headers={
        "Authorization": 'Bearer ' + module.params['cloud_api_key'],
        'User-Agent': 'grafana-ansible-collection',
    })

    if result.status_code == 200:
        return False, True, result.json()
    else:
        return True, False, {"status": result.status_code, 'response': result.json()['message']}


def main():

    module_args = dict(
        name=dict(type='str', required=True),
        version=dict(type='str', required=False, default='latest'),
        stack_slug=dict(type='str', required=True),
        cloud_api_key=dict(type='str', required=True, no_log=True),
        state=dict(type='str', required=False, default='present', choices=['present', 'absent'])
    )

    choice_map = {
        "present": present_cloud_plugin,
        "absent": absent_cloud_plugin,
    }

    module = AnsibleModule(
        argument_spec=module_args
    )

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib('requests'))

    is_error, has_changed, result = choice_map.get(
        module.params['state'])(module)

    if not is_error:
        module.exit_json(changed=has_changed,
                         pluginId=result['pluginId'],
                         pluginName=result['pluginName'],
                         pluginSlug=result['pluginSlug'],
                         current_version=result['version'],
                         latest_version=result['latestVersion'])
    else:
        module.fail_json(msg=result)


if __name__ == '__main__':
    main()
