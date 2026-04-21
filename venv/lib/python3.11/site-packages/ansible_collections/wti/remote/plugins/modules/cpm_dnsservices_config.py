#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (C) 2023 Red Hat Inc.
# Copyright (C) 2023 Western Telematic Inc.
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
# Module to configure WTI network DNS Services Parameters on WTI OOB and PDU devices.
# CPM remote_management
#
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: cpm_dnsservices_config
version_added: "2.10.0"
author: "Western Telematic Inc. (@wtinetworkgear)"
short_description: Set network DNS Services parameters in WTI OOB and PDU devices
description:
    - "Set network DNS Services parameters in WTI OOB and PDU devices"
options:
    cpm_url:
        description:
            - This is the URL of the WTI device to send the module.
        type: str
        required: true
    cpm_username:
        description:
            - This is the Username of the WTI device to send the module. If this value
            - is blank, then the cpm_password is presumed to be a User Token.
        type: str
        required: false
    cpm_password:
        description:
            - This is the Password of the WTI device to send the module. If the
            - cpm_username is blank, this parameter is presumed to be a User Token.
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
        description:
            - Flag to control if the lookup will observe HTTP proxy environment variables when present.
        type: bool
        required: false
        default: false
    index:
        description:
            - Index in which DNS Server should be inserted. If not defined entry will start at position one.
        type: list
        elements: int
        required: false
    dnsservers:
        description:
            - Actual DNS Server to send to the WTI device.
        type: list
        elements: str
        required: true
notes:
  - Use C(groups/cpm) in C(module_defaults) to set common options used between CPM modules.
"""

EXAMPLES = """
# Set Network DNS Services Parameters
- name: Set the an DNS Services Parameter for a WTI device
  cpm_dnsservices_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false
    dnsservers: "8.8.8.8"

# Set Network DNS Services Parameters using a User Token
- name: Set the an DNS Services Parameter for a WTI device
  cpm_dnsservices_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: ""
    cpm_password: "randomusertokenfromthewtidevice"
    use_https: true
    validate_certs: false
    dnsservers: "8.8.4.4"

# Sets multiple Network DNS Services Parameters
- name: Set the DNS Services Parameters a WTI device
  cpm_dnsservices_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false
    index:
      - 1
      - 2
    dnsservers:
      - "8.8.8.8"
      - "8.8.4.4"
"""

RETURN = """
data:
  description: The output JSON returned from the commands sent
  returned: always
  type: complex
  contains:
    dnsservices:
      description: Current k/v pairs of interface info for the WTI device after module execution.
      returned: always
      type: dict
      sample: {"servers": [
              {"dnsserver1": [{"ip": "166.216.138.41"}],
               "dnsserver2": [{"ip": "166.216.138.42"}],
               "dnsserver3": [{"ip": "8.8.8.8"}],
               "dnsserver4": [{"ip": ""}]}]}
"""

import base64
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text, to_bytes, to_native
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.urls import open_url, ConnectionError, SSLValidationError


def assemble_json(cpmmodule, existing_interface):
    total_servers = total_indices = 0
    is_changed = 0
    json_load = ""

    indices = []
    servers = []

    for x in range(0, 48):
        indices.insert(x, None)
        servers.insert(x, None)

    index = cpmmodule.params['index']
    if (index is not None):
        if isinstance(index, list):
            for x in index:
                indices.insert(total_indices, (int(to_native(x))) - 1)
                total_indices += 1

    dnsservers = cpmmodule.params['dnsservers']
    if (dnsservers is not None):
        if isinstance(dnsservers, list):
            for x in dnsservers:
                if (total_indices == 0):
                    servers.insert(total_servers, to_native(x))
                else:
                    servers.insert(indices[total_servers], to_native(x))
                total_servers += 1

    if (total_indices > 0):
        if (total_servers != total_indices):
            return None

    for x in range(0, 4):
        if (servers[x] is not None):
            dnsservertag = "dnsserver%d" % (x + 1)
            if (existing_interface["dnsservices"]["servers"][0][dnsservertag][0]["ip"] != servers[x]):
                if (is_changed > 0):
                    json_load = '%s,' % (json_load)
                json_load = '%s"%s": [	{"ip": "%s"}	]' % (json_load, dnsservertag, servers[x])

                is_changed += 1

    if (is_changed > 0):
        json_load = '{"dnsservices": {"servers": [{ %s }]}}' % (json_load)

    return json_load


def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        cpm_url=dict(type='str', required=True),
        cpm_username=dict(type='str', required=False),
        cpm_password=dict(type='str', required=True, no_log=True),
        index=dict(type='list', elements='int', required=False, default=None),
        dnsservers=dict(type='list', elements='str', required=True),
        use_https=dict(type='bool', default=True),
        validate_certs=dict(type='bool', default=True),
        use_proxy=dict(type='bool', default=False)
    )

    result = dict(
        changed=False,
        data=''
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if (len(to_native(module.params['cpm_username'])) > 0):
        auth = to_text(base64.b64encode(to_bytes('{0}:{1}'.format(to_native(module.params['cpm_username']), to_native(module.params['cpm_password'])),
                       errors='surrogate_or_strict')))
        header = {'Content-Type': 'application/json', 'Authorization': "Basic %s" % auth}
    else:
        header = {'Content-Type': 'application/json', 'X-WTI-API-KEY': "%s" % (to_native(module.params['cpm_password']))}

    if module.params['use_https'] is True:
        transport = "https://"
    else:
        transport = "http://"

    fullurl = ("%s%s/api/v2%s/status/dnsservices" % (transport, to_native(module.params['cpm_url']),
               "" if len(to_native(module.params['cpm_username'])) else "/token"))
    method = 'GET'
    try:
        response = open_url(fullurl, data=None, method=method, validate_certs=module.params['validate_certs'], use_proxy=module.params['use_proxy'],
                            headers=header)

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

    result['data'] = json.loads(response.read())
    payload = assemble_json(module, result['data'])

    if module.check_mode:
        if (payload is not None) and (len(payload) > 0):
            result['changed'] = True
    else:
        if (payload is not None) and (len(payload) > 0):
            fullurl = ("%s%s/api/v2%s/config/dnsservices" % (transport, to_native(module.params['cpm_url']),
                       "" if len(to_native(module.params['cpm_username'])) else "/token"))
            method = 'POST'

            try:
                response = open_url(fullurl, data=payload, method=method, validate_certs=module.params['validate_certs'], use_proxy=module.params['use_proxy'],
                                    headers=header)

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
