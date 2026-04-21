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
module: sap_snote

short_description: This module will upload and (de)implements C(SNOTES) in a SAP S4HANA environment.

version_added: "1.0.0"

description:
    - The C(sap_snote) module depends on C(pyrfc) Python library (version 2.4.0 and upwards).
        Depending on distribution you are using, you may need to install additional packages to
        have these available.
    - This module will use the Function Group C(SCWB_API).
    - The C(TMS) must be configured at first.
    - Integrating SNOTES cannot be done via C(DDIC)- or C(SAP*)-User.
options:
    state:
        description:
        - The decision what to do with the SNOTE.
        - Could be C('present'), C('absent')
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
    snote_path:
        description:
        - The path to the extracted SNOTE txt file.
        - The File could be extracted from SAR package.
        - If C(snote_path) is not provided, the C(snote) parameter must be defined.
        - The SNOTE txt file must be at a place where the SAP System is authorized for. For example C(/usr/sap/trans/files).
        required: false
        type: str
    snote:
        description:
        - With the C(snote) paramter only implementation and deimplementation will work.
        - Upload SNOTES to the System is only available if C(snote_path) is provided.
        required: false
        type: str

requirements:
    - pyrfc >= 2.4.0

author:
    - Rainer Leber (@rainerleber)
'''

EXAMPLES = r'''
- name: test snote module
  hosts: localhost
  tasks:
  - name: implement SNOTE
    community.sap_libs.sap_snote:
      conn_username: 'DDIC'
      conn_password: 'Passwd1234'
      host: 192.168.1.100
      sysnr: '01'
      client: '000'
      state: present
      snote_path: /usr/sap/trans/tmp/0002949148.txt

- name: test snote module without path
  hosts: localhost
  tasks:
  - name: deimplement SNOTE
    community.sap_libs.sap_snote:
      conn_username: 'DDIC'
      conn_password: 'Passwd1234'
      host: 192.168.1.100
      sysnr: '01'
      client: '000'
      state: absent
      snote: 0002949148

'''

RETURN = r'''
msg:
    description: A small execution description.
    type: str
    returned: always
    sample: 'SNOTE 000298026 implemented.'
out:
    description: A complete description of the SNOTE implementation. If this is available.
    type: list
    elements: dict
    returned: always
    sample: '{
        "RETURN": [{"ES_MSG": { "MSGNO": "000", "MSGTY": "", "MSGTXT": "", "MSGV1": "" },
                "ET_MSG": [],
                "EV_RC": 0,
                "ET_MISSING_NOTES": [],
                "IT_FILENAME": [{"FILENAME": "/usr/sap/trans/tmp/0002980265.txt"}],
                "IT_NOTES": [{"NUMM": "0002980265", "VERSNO": "0000"}]
                }]}'
'''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from os import path as os_path
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


def check_implementation(conn, snote):
    check_implemented = call_rfc_method(conn, 'SCWB_API_GET_NOTES_IMPLEMENTED', {})
    for snote_list in check_implemented['ET_NOTES_IMPL']:
        if snote in snote_list['NUMM']:
            return True
    return False


def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(default='present', choices=['absent', 'present']),
            conn_username=dict(type='str', required=True),
            conn_password=dict(type='str', required=True, no_log=True),
            host=dict(type='str', required=True),
            sysnr=dict(type='str', default="01"),
            client=dict(type='str', default="000"),
            snote_path=dict(type='str', required=False),
            snote=dict(type='str', required=False),
        ),
        required_one_of=[('snote_path', 'snote')],
        supports_check_mode=False,
    )
    result = dict(changed=False, msg='', out={}, error='')
    raw = ""
    post_check = False

    params = module.params

    state = params['state']
    conn_username = (params['conn_username']).upper()
    conn_password = params['conn_password']
    host = params['host']
    sysnr = (params['sysnr']).zfill(2)
    client = params['client']

    path = params['snote_path']
    snote = params['snote']

    if not HAS_PYRFC_LIBRARY:
        module.fail_json(
            msg=missing_required_lib('pyrfc'),
            exception=ANOTHER_LIBRARY_IMPORT_ERROR)

    if conn_username == "DDIC" or conn_username == "SAP*":
        result['msg'] = 'User C(DDIC) or C(SAP*) not allowed for this operation.'
        module.fail_json(**result)

    # basic RFC connection with pyrfc
    try:
        conn = Connection(user=conn_username, passwd=conn_password, ashost=host, sysnr=sysnr, client=client)
    except Exception as err:
        result['error'] = str(err)
        result['msg'] = 'Something went wrong connecting to the SAP system.'
        module.fail_json(**result)

    # pre evaluation of parameters
    if path is not None:
        if path.endswith('.txt'):
            # splits snote number from path and txt extension
            snote = os_path.basename(os_path.normpath(path)).split('.')[0]
        else:
            result['msg'] = 'The path must include the extracted snote file and ends with txt.'
            module.fail_json(**result)

    pre_check = check_implementation(conn, snote)

    if state == "absent" and pre_check:
        raw = call_rfc_method(conn, 'SCWB_API_NOTES_DEIMPLEMENT', {'IT_NOTES': [snote]})

    if state == "present" and not pre_check:
        if path:
            raw_upload = call_rfc_method(conn, 'SCWB_API_UPLOAD_NOTES', {'IT_FILENAME': [path], 'IT_NOTES': [snote]})
            if raw_upload['EV_RC'] != 0:
                result['out'] = raw_upload
                result['msg'] = raw_upload['ES_MSG']['MSGTXT']
                module.fail_json(**result)

        raw = call_rfc_method(conn, 'SCWB_API_NOTES_IMPLEMENT', {'IT_NOTES': [snote]})
        queued = call_rfc_method(conn, 'SCWB_API_CINST_QUEUE_GET', {})

        if queued['ET_MANUAL_ACTIVITIES']:
            raw = call_rfc_method(conn, 'SCWB_API_CONFIRM_MAN_ACTIVITY', {})

    if raw:
        if raw['EV_RC'] == 0:
            post_check = check_implementation(conn, snote)
            if post_check and state == "present":
                result['changed'] = True
                result['msg'] = 'SNOTE "{0}" implemented.'.format(snote)
            if not post_check and state == "absent":
                result['changed'] = True
                result['msg'] = 'SNOTE "{0}" deimplemented.'.format(snote)
        else:
            result['msg'] = "Something went wrong."
            module.fail_json(**result)
        result['out'] = raw
    else:
        result['msg'] = "Nothing to do."

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
