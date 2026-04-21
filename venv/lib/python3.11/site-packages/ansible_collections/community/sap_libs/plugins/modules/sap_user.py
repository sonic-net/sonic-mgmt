#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Rainer Leber <rainerleber@gmail.com> <rainer.leber@sva.de>
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: sap_user
short_description: This module will manage a user entities in a SAP S4/HANA environment
version_added: "1.0.0"
description:
  - The M(community.sap_libs.sap_user) module depends on C(pyrfc) Python library (version 2.4.0 and upwards).
    Depending on distribution you are using, you may need to install additional packages to
    have these available.
  - This module will use the following user BAPIs to manage user entities.
    - C(BAPI_USER_GET_DETAIL)
    - C(BAPI_USER_DELETE)
    - C(BAPI_USER_CREATE1)
    - C(BAPI_USER_CHANGE)
    - C(BAPI_USER_ACTGROUPS_ASSIGN)
    - C(BAPI_USER_PROFILES_ASSIGN)
    - C(BAPI_USER_UNLOCK)
    - C(BAPI_USER_LOCK)
options:
    state:
        description:
          - The decision what to do with the user.
        default: 'present'
        choices:
          - 'present'
          - 'absent'
          - 'lock'
          - 'unlock'
        required: false
        type: str
    force:
        description:
          - Must be C('True') if the password or type should be overwritten.
        default: False
        required: false
        type: bool
    conn_username:
        description: The required username for the SAP system.
        required: true
        type: str
    conn_password:
        description: The required password for the SAP system.
        required: true
        type: str
    host:
        description: The required host for the SAP system. Can be either an FQDN or IP Address.
        required: true
        type: str
    sysnr:
        description:
          - The system number of the SAP system.
          - You must quote the value to ensure retaining the leading zeros.
        default: '00'
        type: str
    client:
        description:
          - The client number to connect to.
          - You must quote the value to ensure retaining the leading zeros.
        default: '000'
        type: str
    username:
        description:
          - The username.
        type: str
        required: true
    firstname:
        description:
          - The Firstname of the user in the SAP system.
        type: str
        required: false
    lastname:
        description:
          - The lastname of the user in the SAP system.
        type: str
        required: false
    email:
        description:
          - The email address of the user in the SAP system.
        type: str
        required: false
    password:
        description:
          - The password for the user in the SAP system.
        type: str
        required: false
    useralias:
        description:
          - The alias for the user in the SAP system.
        type: str
        required: false
    user_type:
        description:
          - The type for the user in the SAP system.
          - C('A') Dialog user, C('B') System User, C('C') Communication User,
            C('S') Service User, C('L') Reference User.
          - Must be in uppercase.
        type: str
        required: false
        default: 'A'
        choices: ['A', 'B', 'C', 'S', 'L']
    company:
        description:
          - The specific company the user belongs to.
          - The company name must be available in the SAP system.
        type: str
        required: false
    profiles:
        description:
          - Assign profiles to the user.
          - Should be in uppercase, for example C('SAP_NEW') or C('SAP_ALL').
        type: list
        elements: str
        default: ['']
        required: false
    roles:
        description:
          - Assign roles to the user.
        type: list
        elements: str
        default: ['']
        required: false

requirements:
    - pyrfc >= 2.4.0
author:
    - Rainer Leber (@rainerleber)
notes:
    - Does not support C(check_mode).
'''

EXAMPLES = r'''
- name: Create SAP User
  community.sap_libs.sap_user:
    conn_username: 'DDIC'
    conn_password: 'Test123'
    host: 192.168.1.150
    sysnr: '01'
    client: '000'
    state: present
    username: ADMIN
    firstname: first_admin
    lastname: last_admin
    email: admin@test.de
    password: Test123456
    useralias: ADMIN
    company: DEFAULT_COMPANY
    roles:
      - "SAP_ALL"

- name: Force change SAP User
  community.sap_libs.sap_user:
    conn_username: 'DDIC'
    conn_password: 'Test123'
    host: 192.168.1.150
    sysnr: '01'
    client: '000'
    state: present
    force: true
    username: ADMIN
    firstname: first_admin
    lastname: last_admin
    email: admin@test.de
    password: Test123456
    useralias: ADMIN
    company: DEFAULT_COMPANY
    roles:
      - "SAP_ALL"

- name: Delete SAP User
  community.sap_libs.sap_user:
    conn_username: 'DDIC'
    conn_password: 'Test123'
    host: 192.168.1.150
    sysnr: '01'
    client: '000'
    state: absent
    force: true
    username: ADMIN

- name: Unlock SAP User
  community.sap_libs.sap_user:
    conn_username: 'DDIC'
    conn_password: 'Test123'
    host: 192.168.1.150
    sysnr: '01'
    client: '000'
    state: unlock
    force: true
    username: ADMIN
'''

RETURN = r'''
msg:
  description: A small execution description about the user action.
  type: str
  returned: always
  sample: 'User ADMIN created'
out:
  description: A detailed description about the user action.
  type: list
  elements: dict
  returned: on success
  sample: [...,{
              "RETURN": [
            {
                "FIELD": "BNAME",
                "ID": "01",
                "LOG_MSG_NO": "000000",
                "LOG_NO": "",
                "MESSAGE": "User ADMIN created",
                "MESSAGE_V1": "ADMIN",
                "MESSAGE_V2": "",
                "MESSAGE_V3": "",
                "MESSAGE_V4": "",
                "NUMBER": "102",
                "PARAMETER": "",
                "ROW": 0,
                "SYSTEM": "",
                "TYPE": "S"
            }
          ],
          "SAPUSER_UUID_HIST": []}]
'''
from ansible.module_utils.basic import AnsibleModule, missing_required_lib
import traceback
import datetime
try:
    from pyrfc import Connection
except ImportError:
    HAS_PYRFC_LIBRARY = False
    PYRFC_LIBRARY_IMPORT_ERROR = traceback.format_exc()
else:
    PYRFC_LIBRARY_IMPORT_ERROR = None
    HAS_PYRFC_LIBRARY = True


def add_to_dict(target_dict, target_key, value):
    # Adds the given value to a dict as the key
    # check if the given key is in the given dict yet
    if target_key in target_dict:
        return False
    target_dict[target_key] = value
    return True


def call_rfc_method(connection, method_name, kwargs):
    # PyRFC call function
    return connection.call(method_name, **kwargs)


def build_rfc_user_params(username, firstname, lastname, email, raw_password,
                          useralias, user_type, raw_company, user_change, force):
    """Creates RFC parameters for Creating users"""
    # define dicts in batch
    params = dict()
    address = dict()
    password = dict()
    alias = dict()
    logondata = dict()
    company = dict()
    # for change parameters
    addressx = dict()
    passwordx = dict()
    logondatax = dict()
    companyx = dict()
    # define username
    add_to_dict(params, 'USERNAME', username)
    # define Address
    add_to_dict(address, 'FIRSTNAME', firstname)
    add_to_dict(address, 'LASTNAME', lastname)
    add_to_dict(address, 'E_MAIL', email)
    # define Password
    add_to_dict(password, 'BAPIPWD', raw_password)
    # define Alias
    add_to_dict(alias, 'USERALIAS', useralias)
    # define LogonData
    add_to_dict(logondata, 'GLTGV', datetime.date.today())
    add_to_dict(logondata, 'GLTGB', '20991231')
    add_to_dict(logondata, 'USTYP', user_type)
    # define company
    add_to_dict(company, 'COMPANY', raw_company)
    params['LOGONDATA'] = logondata
    params['ADDRESS'] = address
    params['COMPANY'] = company
    params['ALIAS'] = alias
    params['PASSWORD'] = password
    # add change if user exists
    if user_change and force:
        add_to_dict(addressx, 'FIRSTNAME', 'X')
        add_to_dict(addressx, 'LASTNAME', 'X')
        add_to_dict(addressx, 'E_MAIL', 'X')
        # define Password
        add_to_dict(passwordx, 'BAPIPWD', 'X')
        # define LogonData
        add_to_dict(logondatax, 'USTYP', 'X')
        # define company
        add_to_dict(companyx, 'COMPANY', 'X')
        params['LOGONDATAX'] = logondatax
        params['ADDRESSX'] = addressx
        params['COMPANYX'] = companyx
        params['PASSWORDX'] = passwordx
    return params


def user_role_assignment_build_rfc_params(roles, username):
    rfc_table = []

    for role_name in roles:
        table_row = {'AGR_NAME': role_name}

        add_to_dict(table_row, 'FROM_DAT', datetime.date.today())
        add_to_dict(table_row, 'TO_DAT', '20991231')

        rfc_table.append(table_row)

    return {
        'USERNAME': username,
        'ACTIVITYGROUPS': rfc_table
    }


def user_profile_assignment_build_rfc_params(profiles, username):
    rfc_table = []

    for profile_name in profiles:
        table_row = {'BAPIPROF': profile_name}
        rfc_table.append(table_row)

    return {
        'USERNAME': username,
        'PROFILES': rfc_table
    }


def check_user(user_detail):
    if len(user_detail['RETURN']) > 0:
        for sub in user_detail['RETURN']:
            if sub['NUMBER'] == '124':
                return False
    return True


def return_analysis(raw):
    change = False
    failed = False
    for state in raw['RETURN']:
        if state['TYPE'] == "E":
            if state['NUMBER'] == '224' or state['NUMBER'] == '124':
                change = False
            else:
                failed = True
        if state['TYPE'] == "S":
            if state['NUMBER'] != '029':
                change = True
        if state['TYPE'] == "W":
            if state['NUMBER'] == '049' or state['NUMBER'] == '047':
                change = True
            if state['NUMBER'] == '255':
                change = True
    return [{"change": change}, {"failed": failed}]


def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            # logical values
            state=dict(default='present', choices=[
                       'absent', 'present', 'lock', 'unlock']),
            force=dict(type='bool', default=False),
            # values for connection
            conn_username=dict(type='str', required=True),
            conn_password=dict(type='str', required=True, no_log=True),
            host=dict(type='str', required=True),
            sysnr=dict(type='str', default="00"),
            client=dict(type='str', default="000"),
            # values for the new or existing user
            username=dict(type='str', required=True),
            firstname=dict(type='str', required=False),
            lastname=dict(type='str', required=False),
            email=dict(type='str', required=False),
            password=dict(type='str', required=False, no_log=True),
            useralias=dict(type='str', required=False),
            user_type=dict(default="A",
                           choices=['A', 'B', 'C', 'S', 'L']),
            company=dict(type='str', required=False),
            # values for profile must a list
            # Example ["SAP_NEW", "SAP_ALL"]
            profiles=dict(type='list', elements='str', default=[""]),
            # values for roles must a list
            roles=dict(type='list', elements='str', default=[""]),
        ),
        supports_check_mode=False,
        required_if=[('state', 'present', ['useralias', 'company'])]
    )
    result = dict(changed=False, msg='', out='')
    count = 0
    raw = ""

    params = module.params

    state = params['state']
    conn_username = (params['conn_username']).upper()
    conn_password = params['conn_password']
    host = params['host']
    sysnr = params['sysnr']
    client = params['client']

    username = (params['username']).upper()
    firstname = params['firstname']
    lastname = params['lastname']
    email = params['email']
    password = params['password']
    force = params['force']
    if not params['useralias'] is None:
        useralias = (params['useralias']).upper()
    user_type = (params['user_type']).upper()
    company = params['company']

    profiles = params['profiles']
    roles = params['roles']

    if not HAS_PYRFC_LIBRARY:
        module.fail_json(
            msg=missing_required_lib('pyrfc'),
            exception=PYRFC_LIBRARY_IMPORT_ERROR)

    # basic RFC connection with pyrfc
    try:
        conn = Connection(user=conn_username, passwd=conn_password, ashost=host, sysnr=sysnr, client=client)
    except Exception as err:
        result['error'] = str(err)
        result['msg'] = 'Something went wrong connecting to the SAP system.'
        module.fail_json(**result)

    # user details
    user_detail = call_rfc_method(conn, 'BAPI_USER_GET_DETAIL', {'USERNAME': username})
    user_exists = check_user(user_detail)

    if state == "absent":
        if user_exists:
            raw = call_rfc_method(conn, 'BAPI_USER_DELETE', {'USERNAME': username})

    if state == "present":
        user_params = build_rfc_user_params(username, firstname, lastname, email, password, useralias, user_type, company, user_exists, force)
        if not user_exists:
            raw = call_rfc_method(conn, 'BAPI_USER_CREATE1', user_params)

        if user_exists:
            # check for address changes when user exists
            user_no_changes = all((user_detail.get('ADDRESS')).get(k) == v for k, v in (user_params.get('ADDRESS')).items())
            if not user_no_changes or force:
                raw = call_rfc_method(conn, 'BAPI_USER_CHANGE', user_params)

        call_rfc_method(conn, 'BAPI_USER_ACTGROUPS_ASSIGN', user_role_assignment_build_rfc_params(roles, username))

        call_rfc_method(conn, 'BAPI_USER_PROFILES_ASSIGN', user_profile_assignment_build_rfc_params(profiles, username))

    if state == "unlock":
        if user_exists:
            raw = call_rfc_method(conn, 'BAPI_USER_UNLOCK', {'USERNAME': username})

    if state == "lock":
        if user_exists:
            raw = call_rfc_method(conn, 'BAPI_USER_LOCK', {'USERNAME': username})

    # analyse return value
    if raw != '':
        analysed = return_analysis(raw)

        result['out'] = raw

        result['changed'] = analysed[0]['change']
        for msgs in raw['RETURN']:
            if count > 0:
                result['msg'] = result['msg'] + '\n'
            result['msg'] = result['msg'] + msgs['MESSAGE']
            count = count + 1

        if analysed[1]['failed']:
            module.fail_json(**result)
    else:
        result['msg'] = "No changes where made."

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
