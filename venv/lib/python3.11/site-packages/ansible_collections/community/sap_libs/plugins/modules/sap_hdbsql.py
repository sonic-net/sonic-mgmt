#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Rainer Leber <rainerleber@gmail.com>
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
module: sap_hdbsql
short_description: Ansible Module to execute SQL on SAP HANA
version_added: "1.0.0"
description: This module executes SQL statements on HANA with hdbsql.
options:
    sid:
        description: The system ID.
        type: str
        required: false
    bin_path:
        description: The path to the hdbsql binary.
        type: str
        required: false
    instance:
        description: The instance number.
        type: str
        required: true
    user:
        description: A dedicated username. The user could be also in hdbuserstore.
        type: str
        default: SYSTEM
    userstore:
        description: If C(true), the user must be in hdbuserstore.
        type: bool
        default: false
    password:
        description:
          - The password to connect to the database.
          - "B(Note:) Since the passwords have to be passed as command line arguments, I(userstore=true) should
            be used whenever possible, as command line arguments can be seen by other users
            on the same machine."
        type: str
    autocommit:
        description: Autocommit the statement.
        type: bool
        default: true
    host:
        description: The Host IP address. The port can be defined as well.
        type: str
    database:
        description: Define the database on which to connect.
        type: str
    encrypted:
        description: Use encrypted connection.
        type: bool
        default: false
    filepath:
        description:
        - One or more files each containing one SQL query to run.
        - Must be a string or list containing strings.
        type: list
        elements: path
    query:
        description:
        - SQL query to run.
        - Must be a string or list containing strings. Please note that if you supply a string, it will be split by commas (C(,)) to a list.
          It is better to supply a one-element list instead to avoid mangled input.
        type: list
        elements: str
notes:
    - Does not support C(check_mode). Always reports that the state has changed even if no changes have been made.
author:
    - Rainer Leber (@rainerleber)
'''

EXAMPLES = r'''
- name: Simple select query
  community.sap_libs.sap_hdbsql:
    sid: "hdb"
    instance: "01"
    password: "Test123"
    query: select user_name from users

- name: RUN select query with host port
  community.sap_libs.sap_hdbsql:
    sid: "hdb"
    instance: "01"
    password: "Test123"
    host: "10.10.2.4:30001"
    query: select user_name from users

- name: Run several queries
  community.sap_libs.sap_hdbsql:
    sid: "hdb"
    instance: "01"
    password: "Test123"
    query:
    - select user_name from users
    - select * from SYSTEM
    host: "localhost"
    autocommit: False

- name: Run several queries with path
  community.sap_libs.sap_hdbsql:
    bin_path: "/usr/sap/HDB/HDB01/exe/hdbsql"
    instance: "01"
    password: "Test123"
    query:
    - select user_name from users
    - select * from users
    host: "localhost"
    autocommit: False

- name: Run several queries from file
  community.sap_libs.sap_hdbsql:
    sid: "hdb"
    instance: "01"
    password: "Test123"
    filepath:
    - /tmp/HANA_CPU_UtilizationPerCore_2.00.020+.txt
    - /tmp/HANA.txt
    host: "localhost"

- name: Run several queries from user store
  community.sap_libs.sap_hdbsql:
    sid: "hdb"
    instance: "01"
    user: hdbstoreuser
    userstore: true
    query:
    - select user_name from users
    - select * from users
    autocommit: False
'''

RETURN = r'''
query_result:
    description: List containing results of all queries executed (one sublist for every query).
    returned: on success
    type: list
    elements: list
    sample: [[{"Column": "Value1"}, {"Column": "Value2"}], [{"Column": "Value1"}, {"Column": "Value2"}]]
'''

import csv
from ansible.module_utils.basic import AnsibleModule
from io import StringIO
from ansible.module_utils.common.text.converters import to_native


def csv_to_list(rawcsv):
    reader_raw = csv.DictReader(StringIO(rawcsv))
    reader = [dict((k, v.strip()) for k, v in row.items()) for row in reader_raw]
    return list(reader)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            sid=dict(type='str', required=False),
            bin_path=dict(type='str', required=False),
            instance=dict(type='str', required=True),
            encrypted=dict(type='bool', default=False),
            host=dict(type='str', required=False),
            user=dict(type='str', default="SYSTEM"),
            userstore=dict(type='bool', default=False),
            password=dict(type='str', no_log=True),
            database=dict(type='str', required=False),
            query=dict(type='list', elements='str', required=False),
            filepath=dict(type='list', elements='path', required=False),
            autocommit=dict(type='bool', default=True),
        ),
        required_one_of=[('query', 'filepath'), ('sid', 'instance')],
        required_if=[('userstore', False, ['password'])],
        supports_check_mode=False,
    )
    rc, out, err, out_raw = [0, [], "", ""]

    params = module.params

    sid = params['sid']
    bin_path = params['bin_path']
    instance = params['instance']
    user = params['user']
    userstore = params['userstore']
    password = params['password']
    autocommit = params['autocommit']
    host = params['host']
    database = params['database']
    encrypted = params['encrypted']

    filepath = params['filepath']
    query = params['query']

    if bin_path is None:
        bin_path = "/usr/sap/{sid}/HDB{instance}/exe/hdbsql".format(sid=sid.upper(), instance=instance)

    try:
        command = [module.get_bin_path(bin_path, required=True)]
    except Exception as e:
        module.fail_json(msg='Failed to find hdbsql at the expected path "{0}".Please check SID and instance number: "{1}"'.format(bin_path, to_native(e)))

    if encrypted is True:
        command.extend(['-attemptencrypt'])
    if autocommit is False:
        command.extend(['-z'])
    if host is not None:
        command.extend(['-n', host])
    if database is not None:
        command.extend(['-d', database])
    # -x Suppresses additional output, such as the number of selected rows in a result set.
    if userstore:
        command.extend(['-x', '-U', user])
    else:
        command.extend(['-x', '-i', instance, '-u', user, '-p', password])

    if filepath is not None:
        command.extend(['-E 3', '-I'])
        for p in filepath:
            # makes a command like hdbsql -i 01 -u SYSTEM -p secret123# -I /tmp/HANA_CPU_UtilizationPerCore_2.00.020+.txt,
            # iterates through files and append the output to var out.
            query_command = command + [p]
            (rc, out_raw, err) = module.run_command(query_command)
            out.append(csv_to_list(out_raw))
    if query is not None:
        for q in query:
            # makes a command like hdbsql -i 01 -u SYSTEM -p secret123# "select user_name from users",
            # iterates through multiple commands and append the output to var out.
            query_command = command + [q]
            (rc, out_raw, err) = module.run_command(query_command)
            out.append(csv_to_list(out_raw))
    changed = True

    module.exit_json(changed=changed, rc=rc, query_result=out, stderr=err)


if __name__ == '__main__':
    main()
