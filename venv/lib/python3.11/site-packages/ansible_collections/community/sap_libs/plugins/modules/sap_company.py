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
module: sap_company

short_description: This module will manage a company entities in a SAP S4HANA environment

version_added: "1.0.0"

description:
    - The M(community.sap_libs.sap_user) module depends on C(pyrfc) Python library (version 2.4.0 and upwards).
      Depending on distribution you are using, you may need to install additional packages to
      have these available.
    - This module will use the company BAPIs C(BAPI_COMPANY_CLONE) and C(BAPI_COMPANY_DELETE) to manage company entities.

options:
    state:
        description:
        - The decision what to do with the company.
        default: 'present'
        choices:
        - 'present'
        - 'absent'
        required: false
        type: str
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
        required: false
        default: '01'
        type: str
    client:
        description:
        - The client number to connect to.
        - You must quote the value to ensure retaining the leading zeros.
        required: false
        default: '000'
        type: str
    company_id:
        description: The company id.
        required: true
        type: str
    name:
        description: The company name.
        required: false
        type: str
    name_2:
        description: Additional company name.
        required: false
        type: str
    country:
        description: The country code for the company. For example, C('DE').
        required: false
        type: str
    time_zone:
        description: The timezone.
        required: false
        type: str
    city:
        description: The city where the company is located.
        required: false
        type: str
    post_code:
        description: The post code from the city.
        required: false
        type: str
    street:
        description: Street where the company is located.
        required: false
        type: str
    street_no:
        description: Street number.
        required: false
        type: str
    e_mail:
        description: General E-Mail address.
        required: false
        type: str

requirements:
    - pyrfc >= 2.4.0

author:
    - Rainer Leber (@rainerleber)

notes:
    - Does not support C(check_mode).
'''

EXAMPLES = r'''
- name: Create SAP Company
  community.sap_libs.sap_company:
    conn_username: 'DDIC'
    conn_password: 'HECtna2021#'
    host: 100.0.201.20
    sysnr: '01'
    client: '000'
    state: present
    company_id: "Comp_ID"
    name: "Test_comp"
    name_2: "LTD"
    country: "DE"
    time_zone: "UTC"
    city: "City"
    post_code: "12345"
    street: "test_street"
    street_no: "1"
    e_mail: "test@test.de"

# pass in a message and have changed true
- name: Delete SAP Company
  community.sap_libs.sap_company:
    conn_username: 'DDIC'
    conn_password: 'HECtna2021#'
    host: 100.0.201.20
    sysnr: '01'
    client: '000'
    state: absent
    company_id: "Comp_ID"
    name: "Test_comp"
    name_2: "LTD"
    country: "DE"
    time_zone: "UTC"
    city: "City"
    post_code: "12345"
    street: "test_street"
    street_no: "1"
    e_mail: "test@test.de"
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
msg:
  description: A small execution description.
  type: str
  returned: always
  sample: 'Company address COMP_ID created'
out:
  description: A complete description of the executed tasks. If this is available.
  type: list
  elements: dict
  returned: always
  sample: '{
        "RETURN": [
                {
                "FIELD": "",
                "ID": "01",
                "LOG_MSG_NO": "000000",
                "LOG_NO": "",
                "MESSAGE": "Company address COMP_ID created",
                "MESSAGE_V1": "COMP_ID",
                "MESSAGE_V2": "",
                "MESSAGE_V3": "",
                "MESSAGE_V4": "",
                "NUMBER": "078",
                "PARAMETER": "",
                "ROW": 0,
                "SYSTEM": "",
                "TYPE": "S"
                }
            ]
        }
    }'
'''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
import traceback
try:
    from pyrfc import Connection
except ImportError:
    HAS_PYRFC_LIBRARY = False
    ANOTHER_LIBRARY_IMPORT_ERROR = traceback.format_exc()
else:
    ANOTHER_LIBRARY_IMPORT_ERROR = None
    HAS_PYRFC_LIBRARY = True


def call_rfc_method(connection, method_name, kwargs):
    # PyRFC call function
    return connection.call(method_name, **kwargs)


def build_company_params(name, name_2, country, time_zone, city, post_code, street, street_no, e_mail):
    # Creates RFC parameters for creating organizations
    # define dicts in batch
    params = dict()
    # define company name
    params['NAME'] = name
    params['NAME_2'] = name_2
    # define location
    params['COUNTRY'] = country
    params['TIME_ZONE'] = time_zone
    params['CITY'] = city
    params['POSTL_COD1'] = post_code
    params['STREET'] = street
    params['STREET_NO'] = street_no
    # define communication
    params['E_MAIL'] = e_mail
    # return dict
    return params


def return_analysis(raw):
    change = False
    failed = False
    msg = raw['RETURN'][0]['MESSAGE']
    for state in raw['RETURN']:
        if state['TYPE'] == "E":
            if state['NUMBER'] == '081':
                change = False
            else:
                failed = True
        if state['TYPE'] == "S":
            if state['NUMBER'] != '079':
                change = True
            else:
                msg = "No changes where made."
    return [{"change": change}, {"failed": failed}, {"msg": msg}]


def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(default='present', choices=['absent', 'present']),
            conn_username=dict(type='str', required=True),
            conn_password=dict(type='str', required=True, no_log=True),
            host=dict(type='str', required=True),
            sysnr=dict(type='str', default="01"),
            client=dict(type='str', default="000"),
            company_id=dict(type='str', required=True),
            name=dict(type='str', required=False),
            name_2=dict(type='str', required=False),
            country=dict(type='str', required=False),
            time_zone=dict(type='str', required=False),
            city=dict(type='str', required=False),
            post_code=dict(type='str', required=False),
            street=dict(type='str', required=False),
            street_no=dict(type='str', required=False),
            e_mail=dict(type='str', required=False),
        ),
        supports_check_mode=False,
    )
    result = dict(changed=False, msg='', out={})
    raw = ""

    params = module.params

    state = params['state']
    conn_username = (params['conn_username']).upper()
    conn_password = params['conn_password']
    host = params['host']
    sysnr = params['sysnr']
    client = params['client']

    company_id = (params['company_id']).upper()
    name = params['name']
    name_2 = params['name_2']
    country = params['country']
    time_zone = params['time_zone']
    city = params['city']
    post_code = params['post_code']
    street = params['street']
    street_no = params['street_no']
    e_mail = params['e_mail']

    if not HAS_PYRFC_LIBRARY:
        module.fail_json(
            msg=missing_required_lib('pyrfc'),
            exception=ANOTHER_LIBRARY_IMPORT_ERROR)

    # basic RFC connection with pyrfc
    try:
        conn = Connection(user=conn_username, passwd=conn_password, ashost=host, sysnr=sysnr, client=client)
    except Exception as err:
        result['error'] = str(err)
        result['msg'] = 'Something went wrong connecting to the SAP system.'
        module.fail_json(**result)

    # build parameter dict of dict
    company_params = build_company_params(name, name_2, country, time_zone, city, post_code, street, street_no, e_mail)

    if state == "absent":
        raw = call_rfc_method(conn, 'BAPI_COMPANY_DELETE', {'COMPANY': company_id})

    if state == "present":
        raw = call_rfc_method(conn, 'BAPI_COMPANY_CLONE',
                              {'METHOD': {'USMETHOD': 'COMPANY_CLONE'}, 'COMPANY': company_id, 'COMP_DATA': company_params})

    analysed = return_analysis(raw)

    result['out'] = raw

    result['changed'] = analysed[0]['change']
    result['msg'] = analysed[2]['msg']

    if analysed[1]['failed']:
        module.fail_json(**result)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
