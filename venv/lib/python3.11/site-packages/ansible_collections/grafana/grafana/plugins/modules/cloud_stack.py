#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Ishan Jain (@ishanjainn)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

DOCUMENTATION = '''
---
module: cloud_stack
author:
  - Ishan Jain (@ishanjainn)
version_added: "0.0.1"
short_description: Manage Grafana Cloud stack
description:
  - Create and delete Grafana Cloud stacks using Ansible.
requirements: [ "requests >= 1.0.0" ]
notes:
  - Does not support C(check_mode).
options:
  name:
    description:
      - Sets the name of stack. Conventionally matches the URL of the instance. For example, C(stackslug.grafana.net).
    type: str
    required: true
  stack_slug:
    description:
      - Sets the subdomain of the Grafana instance. For example, if slug is B(stackslug), the instance URL will be C(https://stackslug.grafana.net).
    type: str
    required: true
  cloud_api_key:
    description:
      - Cloud API Key to authenticate with Grafana Cloud.
    type: str
    required : true
  region:
    description:
      - Sets the region for the Grafana Cloud stack.
    type: str
    default: us
    choices: [ us, us-azure, eu, au, eu-azure, prod-ap-southeast-0, prod-gb-south-0, prod-eu-west-3]
  url:
    description:
      - If you use a custom domain for the instance, you can provide it here. If not provided, Will be set to C(https://stackslug.grafana.net).
    type: str
  org_slug:
    description:
      - Name of the organization under which Cloud stack is created.
    type: str
    required: true
  delete_protection:
    description:
      - Enables or disables deletion protection for the Cloud stack.
      - When set to true, the stack cannot be deleted unless this flag is explicitly disabled.
    type: bool
    default: true
    required: false
  state:
    description:
      - State for the Grafana Cloud stack.
    type: str
    default: present
    choices: [ present, absent ]
'''

EXAMPLES = '''
- name: Create a Grafana Cloud stack
  grafana.grafana.cloud_stack:
    name: stack_name
    stack_slug: stack_name
    cloud_api_key: "{{ grafana_cloud_api_key }}"
    region: eu
    url: https://grafana.company_name.com
    org_slug: org_name
    delete_protection: true
    state: present

- name: Delete a Grafana Cloud stack
  grafana.grafana.cloud_stack:
    name: stack_name
    slug: stack_name
    cloud_api_key: "{{ grafana_cloud_api_key }}"
    org_slug: org_name
    state: absent
'''

RETURN = r'''
  alertmanager_name:
    description: Name of the alertmanager instance.
    returned: always
    type: str
    sample: "stackname-alerts"
  alertmanager_url:
    description: URL of the alertmanager instance.
    returned: always
    type: str
    sample: "https://alertmanager-eu-west-0.grafana.net"
  cluster_slug:
    description: Slug for the cluster where the Grafana stack is deployed.
    returned: always
    type: str
    sample: "prod-eu-west-0"
  id:
    description: ID of the Grafana Cloud stack.
    returned: always
    type: int
    sample: 458182
  loki_url:
    description: URl for the Loki instance.
    returned: always
    type: str
    sample: "https://logs-prod-eu-west-0.grafana.net"
  orgID:
    description: ID of the Grafana Cloud organization.
    returned: always
    type: int
    sample: 652992
  prometheus_url:
    description: URl for the Prometheus instance.
    returned: always
    type: str
    sample: "https://prometheus-prod-01-eu-west-0.grafana.net"
  tempo_url:
    description: URl for the Tempo instance.
    returned: always
    type: str
    sample: "https://tempo-eu-west-0.grafana.net"
  url:
    description: URL of the Grafana Cloud stack.
    returned: always
    type: str
    sample: "https://stackname.grafana.net"
  delete_protection:
    description:
      - Enables or disables deletion protection for the Cloud stack.
      - When set to true, the stack cannot be deleted unless this flag is explicitly disabled.
    returned: always
    type: bool
    sample: true
'''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

__metaclass__ = type


def present_cloud_stack(module):
    if not module.params['url']:
        module.params['url'] = 'https://' + module.params['stack_slug'] + '.grafana.net'

    body = {
        'name': module.params['name'],
        'slug': module.params['stack_slug'],
        'region': module.params['region'],
        'url': module.params['url'],
        'deleteProtection': module.params.get('delete_protection', True),
    }
    api_url = 'https://grafana.com/api/instances'
    headers = {
        "Authorization": 'Bearer ' + module.params['cloud_api_key'],
        'User-Agent': 'grafana-ansible-collection',
    }

    result = requests.post(api_url, json=body, headers=headers)
    if result.status_code == 200:
        return False, True, result.json()
    elif result.status_code in [409, 403] and result.json()['message'] in ["That URL has already been taken, please try an alternate URL", "Hosted instance limit reached"]:
        stack_found = False
        if result.json()['message'] == "That URL has already been taken, please try an alternate URL":
            api_url = 'https://grafana.com/api/orgs/' + module.params['org_slug'] + '/instances'
            result = requests.get(api_url, headers=headers)
            stackInfo = {}
            for stack in result.json()['items']:
                if stack['slug'] == module.params['stack_slug']:
                    stack_found = True
                    stackInfo = stack
            if stack_found:
                if body['deleteProtection'] == stackInfo['deleteProtection']:
                    return False, False, stackInfo
                api_url = f'https://grafana.com/api/instances/{stackInfo["id"]}'
                result = requests.post(api_url, json={'deleteProtection': body['deleteProtection']}, headers=headers)
                if result.status_code != 200:
                    return True, False, {"status": result.status_code, 'response': result.json()['message']}
                return False, True, result.json()
            else:
                return True, False, "Stack is not found under your org"
        elif result.json()['message'] == "Hosted instance limit reached":
            return True, False, "You have reached Maximum number of Cloud Stacks in your Org."
    else:
        return True, False, {"status": result.status_code, 'response': result.json()['message']}


def absent_cloud_stack(module):
    api_url = 'https://grafana.com/api/instances/' + module.params['stack_slug']

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
        stack_slug=dict(type='str', required=True),
        cloud_api_key=dict(type='str', required=True, no_log=True),
        region=dict(type='str', required=False, default='us',
                    choices=['us', 'us-azure', 'eu', 'au', 'eu-azure', 'prod-ap-southeast-0', 'prod-gb-south-0',
                             'prod-eu-west-3']),
        url=dict(type='str', required=False),
        org_slug=dict(type='str', required=True),
        state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
        delete_protection=dict(type=bool, required=False),
    )

    choice_map = {
        "present": present_cloud_stack,
        "absent": absent_cloud_stack,
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
                         alertmanager_name=result['amInstanceName'],
                         url=result['url'], id=result['id'],
                         cluster_slug=result['clusterName'],
                         orgID=result['orgId'],
                         loki_url=result['hlInstanceUrl'],
                         prometheus_url=result['hmInstancePromUrl'],
                         tempo_url=result['htInstanceUrl'],
                         alertmanager_url=result['amInstanceUrl'],
                         delete_protection=result['deleteProtection'])
    else:
        module.fail_json(msg=result)


if __name__ == '__main__':
    main()
