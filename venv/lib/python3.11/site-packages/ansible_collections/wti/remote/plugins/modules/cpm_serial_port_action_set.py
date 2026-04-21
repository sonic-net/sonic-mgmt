#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (C) 2019 Red Hat Inc.
# Copyright (C) 2019 Western Telematic Inc.
#
# GNU General Public License v3.0+
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# Module to execute WTI Serial Port Connection commands on WTI OOB and PDU devices.
# CPM remote_management
#
from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
---
module: cpm_serial_port_action_set
version_added: "2.9.0"
author: "Western Telematic Inc. (@wtinetworkgear)"
short_description: Set Serial port connection/disconnection commands in WTI OOB and PDU devices
description:
    - "Set Serial port connection/disconnection commands in WTI OOB and PDU devices"
options:
    cpm_url:
        description:
            - This is the URL of the WTI device to send the module.
        type: str
        required: true
    cpm_username:
        description:
            - This is the Username of the WTI device to send the module.
        type: str
        required: true
    cpm_password:
        description:
            - This is the Password of the WTI device to send the module.
        type: str
        required: true
    use_https:
        description:
            - Designates to use an https connection or http connection.
        type: bool
        required: false
        default: true
    validate_certs:
        description:
            - If false, SSL certificates will not be validated. This should only be used
            - on personally controlled sites using self-signed certificates.
        type: bool
        required: false
        default: true
    use_proxy:
        description: Flag to control if the lookup will observe HTTP proxy environment variables when present.
        type: bool
        required: false
        default: false
    port:
        description:
            - This is the port number that is getting the action performed on.
        type: int
        required: true
    portremote:
        description:
            - This is the port number that is getting the action performed on.
        type: int
        required: false
    action:
        description:
            - This is the baud rate to assign to the port.
            - 1=Connect, 2=Disconnect
        type: int
        required: false
        choices: [ 1, 2 ]

notes:
  - Use C(groups/cpm) in C(module_defaults) to set common options used between CPM modules.
"""

EXAMPLES = """
# Set Serial Port Action (Connect)
- name: Connect port 2 to port 3 of a WTI device
  cpm_serial_port_action_set:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false
    port: "2"
    portremote: "3"
    action: "1"

# Set Serial port Action (Disconnect)
- name: Disconnect port 2 and 3 of a WTI device
  cpm_serial_port_action_set:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false
    port: "2"
    action: "2"
"""

RETURN = """
data:
    description: The output JSON returned from the commands sent
    returned: always
    type: str
"""

import base64
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text, to_bytes, to_native
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.urls import open_url, ConnectionError, SSLValidationError


def assemble_json(cpmmodule, existing_serial):
    error_int = 0
    error_json = None
    json_load = None

    items = len(existing_serial['ports'])

    for x in range(0, items):
        if (existing_serial["ports"][x]["port"] == to_native(cpmmodule.params["port"])):
            json_load = '%s - match and is %s' % (json_load, existing_serial["ports"][x]["connstatus"])
            if ((cpmmodule.params["action"] == 1) & (existing_serial["ports"][x]["connstatus"] != "Free")):
                error_json = '{"status": {"code": "1", "text": "port %s is busy"}}' % (to_native(cpmmodule.params["port"]))
                error_int = error_int | 1
            if ((cpmmodule.params["action"] == 2) & (existing_serial["ports"][x]["connstatus"] == "Free")):
                error_json = '{"status": {"code": "2", "text": "port is already free"}}'
                error_int = error_int | 2

        if (existing_serial["ports"][x]["port"] == to_native(cpmmodule.params["portremote"])):
            json_load = '%s - match and is %s' % (json_load, existing_serial["ports"][x]["connstatus"])
            if ((cpmmodule.params["action"] == 1) & (existing_serial["ports"][x]["connstatus"] != "Free")):
                error_json = '{"status": {"code": "3", "text": "portremote %s is busy"}}' % (to_native(cpmmodule.params["portremote"]))
                error_int = error_int | 4

    if (error_int == 0):
        json_load = '{"serialports": {"port": %s, "action": %s' % (to_native(cpmmodule.params["port"]), to_native(cpmmodule.params["action"]))
        if (cpmmodule.params["portremote"] is not None):
            json_load = '%s, "portremote": %s' % (json_load, to_native(cpmmodule.params["portremote"]))
        json_load = '%s }}' % (json_load)
    else:
        json_load = None
    return json_load, error_json


def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        cpm_url=dict(type='str', required=True),
        cpm_username=dict(type='str', required=True),
        cpm_password=dict(type='str', required=True, no_log=True),
        use_https=dict(type='bool', default=True),
        validate_certs=dict(type='bool', default=True),
        use_proxy=dict(type='bool', default=False),
        port=dict(type='int', required=True),
        portremote=dict(type='int', required=False),
        action=dict(type='int', required=False, default=None, choices=[1, 2])
    )

    result = dict(
        changed=False,
        data=''
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    auth = to_text(base64.b64encode(to_bytes('{0}:{1}'.format(to_native(module.params['cpm_username']), to_native(module.params['cpm_password'])),
                   errors='surrogate_or_strict')))

    if module.params['use_https'] is True:
        protocol = "https://"
    else:
        protocol = "http://"

    tempports = to_native(module.params['port'])
    if (len(to_native(module.params['portremote']))):
        tempports = '%s,%s' % (tempports, to_native(module.params['portremote']))

    fullurl = ("%s%s/api/v2/config/serialportsaction?ports=%s" % (protocol, to_native(module.params['cpm_url']), to_native(tempports)))
    method = 'GET'
    try:
        response = open_url(fullurl, data=None, method=method, validate_certs=module.params['validate_certs'], use_proxy=module.params['use_proxy'],
                            headers={'Content-Type': 'application/json', 'Authorization': "Basic %s" % auth})

    except HTTPError as e:
        fail_json = dict(msg='GET: Received HTTP error for {0} : {1}'.format(fullurl, to_native(e)), changed=False)
        module.fail_json(**fail_json)
    except URLError as e:
        fail_json = dict(msg='GET: Failed lookup url for {0} : {1}'.format(fullurl, to_native(e)), changed=False)
        module.fail_json(**fail_json)
    except SSLValidationError as e:
        fail_json = dict(msg='GET: Error validating the server''s certificate for {0} : {1}'.format(fullurl, to_native(e)), changed=False)
        module.fail_json(**fail_json)
    except ConnectionError as e:
        fail_json = dict(msg='GET: Error connecting to {0} : {1}'.format(fullurl, to_native(e)), changed=False)
        module.fail_json(**fail_json)

#    result['data'] = json.loads(response.read())
    payload, payload_error = assemble_json(module, json.loads(response.read()))

    if (payload_error is not None):
        result['data'] = payload_error
    else:
        result['data'] = payload

    if module.check_mode:
        if payload is not None:
            result['changed'] = True
    else:
        if payload is not None:
            fullurl = ("%s%s/api/v2/config/serialportsaction" % (protocol, to_native(module.params['cpm_url'])))
            result['data'] = payload
            method = 'POST'

            try:
                response = open_url(fullurl, data=payload, method=method, validate_certs=module.params['validate_certs'], use_proxy=module.params['use_proxy'],
                                    headers={'Content-Type': 'application/json', 'Authorization': "Basic %s" % auth})

            except HTTPError as e:
                fail_json = dict(msg='POST: Received HTTP error for {0} : {1}'.format(fullurl, to_native(e)), changed=False)
                module.fail_json(**fail_json)
            except URLError as e:
                fail_json = dict(msg='POST: Failed lookup url for {0} : {1}'.format(fullurl, to_native(e)), changed=False)
                module.fail_json(**fail_json)
            except SSLValidationError as e:
                fail_json = dict(msg='POST: Error validating the server''s certificate for {0} : {1}'.format(fullurl, to_native(e)), changed=False)
                module.fail_json(**fail_json)
            except ConnectionError as e:
                fail_json = dict(msg='POST: Error connecting to {0} : {1}'.format(fullurl, to_native(e)), changed=False)
                module.fail_json(**fail_json)

            result['changed'] = True
            result['data'] = json.loads(response.read())

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
