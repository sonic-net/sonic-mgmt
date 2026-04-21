#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, téïcée (www.teicee.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.basic import AnsibleModule, missing_required_lib

DOCUMENTATION = '''
---
module: user
author:
  - Mathieu Valois, téïcée
version_added: "0.0.1"
short_description: Manage Users in Grafana
description:
  - Create, Update and delete Users using Ansible.
requirements: [ "requests >= 1.0.0" ]
notes:
  - Does not support C(check_mode).
  - Does not support C(Idempotency).
options:
  grafana_url:
    description:
      - URL of the Grafana instance.
    type: str
    required: true
  admin_name:
    description:
      - Grafana admin username
    type: str
    required : true
  admin_password:
    description:
      - Grafana admin password
    type: str
    required : true
  login:
    description:
      - Login of the user
    type: str
    required : true
  password:
    description:
      - Password of the user. Should be provided if state=present
    type: str
    required : false
  name:
    description:
      - Name of the user.
    type: str
    required : false
  email:
    description:
      - Email address of the user.
    type: str
    required : false
  state:
    description:
      - State for the Grafana User.
    choices: [ present, absent ]
    default: present
    type: str
'''

EXAMPLES = '''
- name: Create/Update a user
  grafana.grafana.user:
    login: "grafana_user"
    password: "{{ lookup('ansible.builtin.password') }}"
    email: "grafana_user@localhost.local
    name: "grafana user"
    grafana_url: "{{ grafana_url }}"
    admin_name: "admin"
    admin_password: "admin"
    state: present

- name: Delete user
  grafana.grafana.user:
    login: "grafana_user"
    grafana_url: "{{ grafana_url }}"
    admin_name: "admin"
    admin_password: "admin"
    state: absent
'''

RETURN = r'''
output:
  description: Dict object containing user information and message.
  returned: On success
  type: dict
  contains:
    id:
      description: The ID for the user.
      returned: on success
      type: int
      sample: 17
    email:
      description: The email for the user.
      returned: on success
      type: str
      sample: grafana_user@localhost.local
    name:
      description: The name for the user.
      returned: on success
      type: str
      sample: grafana user
    login:
      description: The login for the user.
      returned: on success
      type: str
      sample: grafana_user
'''

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


__metaclass__ = type


def _get_user(grafana_url, admin_name, admin_password, login, email=None):
    get_user_url = grafana_url + '/api/users/lookup?loginOrEmail='

    # check if user exists by login provided login
    result = requests.get(f"{get_user_url}{login}", auth=requests.auth.HTTPBasicAuth(
        admin_name, admin_password))
    # if no user has this login, check the email if provided
    if result.status_code == 404 and email is not None:
        result = requests.get(f"{get_user_url}{email}", auth=requests.auth.HTTPBasicAuth(
            admin_name, admin_password))

    if result.status_code == 404:
        return None

    return result.json()


def _set_user_password(grafana_url, admin_name, admin_password, user_id, password):
    """ sets the password for the existing user having user_id.
    admin_name should be a user having users.password:write permission
    """

    set_user_password_url = f"{grafana_url}/api/admin/users/{user_id}/password"

    result = requests.put(set_user_password_url, json={'password': password}, auth=requests.auth.HTTPBasicAuth(
        admin_name, admin_password))

    return result


def present_user(module):

    if module.params['grafana_url'][-1] == '/':
        module.params['grafana_url'] = module.params['grafana_url'][:-1]

    body = {
        'login': module.params['login'],
        'password': module.params['password'],
        'email': module.params['email'],
        'name': module.params['name'],
        'OrgId': module.params['orgid']
    }

    user = _get_user(module.params['grafana_url'], module.params['admin_name'],
                     module.params['admin_password'], module.params['login'], module.params['email'])

    if user is None:
        api_url = module.params['grafana_url'] + '/api/admin/users'
        result = requests.post(api_url, json=body, auth=requests.auth.HTTPBasicAuth(
            module.params['admin_name'], module.params['admin_password']))
    else:
        user_id = user['id']
        api_url = module.params['grafana_url'] + '/api/users'
        result = requests.put(f"{api_url}/{user_id}", json=body, auth=requests.auth.HTTPBasicAuth(
            module.params['admin_name'], module.params['admin_password']))

    if result.status_code == 200:
        return False, True, result.json()

    return True, False, {"status": result.status_code, 'response': result.json()['message']}


def absent_user(module):
    if module.params['grafana_url'][-1] == '/':
        module.params['grafana_url'] = module.params['grafana_url'][:-1]

    user = _get_user(module.params['grafana_url'], module.params['admin_name'],
                     module.params['admin_password'], module.params['login'], module.params['email'])

    if user is None:
        return False, False, "User does not exist"

    user_id = user['id']
    api_url = f"{module.params['grafana_url']}/api/admin/users/{user_id}"
    result = requests.delete(api_url, auth=requests.auth.HTTPBasicAuth(
        module.params['admin_name'], module.params['admin_password']))

    if result.status_code == 200:
        return False, True, result.json()

    return True, False, {"status": result.status_code, 'response': result.json()['message']}


def password_user(module):
    if module.params['grafana_url'][-1] == '/':
        module.params['grafana_url'] = module.params['grafana_url'][:-1]

    # try with new password to check if already changed
    user = _get_user(module.params['grafana_url'], module.params['login'],
                     module.params['password'], module.params['login'], module.params['email'])

    if 'id' in user:
        # Auth is OK, password does not need to be changed
        return False, False, {'message': 'Password has already been changed', 'user': user}

    # from here, we begin password change procedure
    user = _get_user(module.params['grafana_url'], module.params['admin_name'],
                     module.params['admin_password'], module.params['login'], module.params['email'])

    if user is None:
        return True, False, "User does not exist"

    if 'id' not in user:
        return True, False, user

    result = _set_user_password(module.params['grafana_url'], module.params['admin_name'],
                                module.params['admin_password'], user['id'], module.params['password'])

    if result.status_code == 200:
        return False, True, result.json()

    return True, False, result.json()


def main():

    # Grafana admin API is only accessible with basic auth, not token
    # So we shall provide admin name and its password
    module_args = dict(
        admin_name=dict(type='str', required=True),
        admin_password=dict(type='str', required=True, no_log=True),
        login=dict(type='str', required=True),
        password=dict(type='str', required=False, no_log=True),
        email=dict(type='str', required=False),
        name=dict(type='str', required=False),
        orgid=dict(type='int', required=False),
        grafana_url=dict(type='str', required=True),
        state=dict(type='str', required=False, default='present',
                   choices=['present', 'absent', 'update_password'])
    )

    choice_map = {
        "present": present_user,
        "absent": absent_user,
        "update_password": password_user
    }

    module = AnsibleModule(
        argument_spec=module_args
    )

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib('requests'))

    if module.params['state'] in ('present', 'update_password') and 'password' not in module.params:
        module.fail_json(
            msg="Want to create or update user but password is missing")

    is_error, has_changed, result = choice_map.get(
        module.params['state'])(module)

    if not is_error:
        module.exit_json(changed=has_changed, output=result)
    else:
        module.fail_json(msg=result)


if __name__ == '__main__':
    main()
