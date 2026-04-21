#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (C) 2024 Red Hat Inc.
# Copyright (C) 2024 Western Telematic Inc.
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
# Module to configure WTI network WEB Parameters on WTI OOB and PDU devices.
# CPM remote_management
#
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: cpm_web_config
version_added: "2.10.0"
author:
    - "Western Telematic Inc. (@wtinetworkgear)"
short_description: Set network WEB parameters in WTI OOB and PDU devices
description:
    - "Set network WEB parameters in WTI OOB and PDU devices"
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
    trace:
        description:
            - Current state of TRACE requests for thw Web Server.
        type: int
        required: false
        choices: [ 0, 1 ]
    ocsp:
        description:
            - Current state of the Online Certificate Status Protocol (OCSP) for the Web Server.
        type: int
        required: false
        choices: [ 0, 1 ]
    timeout:
        description:
            - Inactivity timeout of a user when logged into the web server (valid from 0 to 9999 minutes) 0 is no timeout.
        type: int
        required: false
    webterm:
        description:
            - Current state of the CLI over Web for the Web Server.
        type: int
        required: false
        choices: [ 0, 1 ]
    interface:
        description:
            - The ethernet port for the SNMP we are defining.
        required: true
        type: str
        choices:
            - eth0
            - eth1
            - ppp0
            - qmimux0
    httpenable:
        description:
            - Activates unsecure WEB for the specified interface.
        type: int
        required: false
        choices: [ 0, 1 ]
    httpport:
        description:
            - Port used by the insecure WEB.
        type: int
        required: false
    httpsenable:
        description:
            - Activates secure WEB for the specified interface.
        type: int
        required: false
        choices: [ 0, 1 ]
    httpsport:
        description:
            - Port used by the secure WEB.
        type: int
        required: false
    harden:
        description:
            - Security level for the WEB the device will respond to 0 = Off, 1 = Medium, 2 = High.
        type: int
        required: false
        choices: [ 0, 1, 2 ]
    tlsmode:
        description:
            - Which TLS the WEB will use 0 = TLSv1.1, 1 = TLSv1.1/TLSv1.2, 2 = TLSv1.2/TLSv1.3, 3 = TLSv1.3
        type: int
        required: false
        choices: [ 0, 1, 2, 3 ]
    hsts:
        description:
            - If HTTP Strict Transport Security (HSTS) is enabled/disabled for the WEB.
        type: int
        required: false
        choices: [ 0, 1 ]
    private_filename:
        description:
            - Private Certificate to be assigned to the Device.
        type: str
        required: false
    signed_filename:
        description:
            - Signed Certificate to be assigned to the Device.
        type: str
        required: false
    inter_filename:
        description:
            - Intermediate Certificate to be assigned to the Device.
        type: str
        required: false
notes:
  - Use C(groups/cpm) in C(module_defaults) to set common options used between CPM modules.
"""

EXAMPLES = """
# Sets the device WEB Parameters
- name: Set the an WEB Parameter for a WTI device
  cpm_snmp_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    interface: "eth0"
    use_https: true
    validate_certs: false
    private_filename: "/tmp/private.key"
    signed_filename: "/tmp/signed.key"
    inter_filename: "/tmp/intermediate.key"

# Sets the device WEB Parameters using a User Token
- name: Set the an WEB Parameter for a WTI device
  cpm_snmp_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: ""
    cpm_password: "randomusertokenfromthewtidevice"
    interface: "eth0"
    use_https: true
    validate_certs: false

# Sets the device WEB Parameters
- name: Set the WEB Parameters a WTI device
  cpm_snmp_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false
"""

RETURN = """
data:
  description: The output JSON returned from the commands sent
  returned: always
  type: complex
  contains:
    trace:
      description: Current state of TRACE requests for the Web Server.
      returned: success
      type: int
      sample: 0
    ocsp:
      description: Current state of the Online Certificate Status Protocol (OCSP) for the Web Server.
      returned: success
      type: int
      sample: 1
    timeout:
      description: Inactivity timeout of a user. (valid from 0 to 9999 minutes) 0 is no timeout.
      returned: success
      type: int
      sample: 0
    webterm:
      description: Current state of the CLI over Web for the Web Server.
      returned: success
      type: int
      sample: 0
    totalports:
      description: Total port being returned from the current call.
      returned: success
      type: int
      sample: 1
    web:
      description: Current k/v pairs of Web info for the WTI device after module execution.
      returned: always
      type: dict
      sample: [{"name":"eth0", "httpenable": "1", "httpport": "80", "httpsenable": "1", "httpsport": "443", "harden": "2",
              "tlsmode": "2", "hsts": "0" }]
"""

import base64
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text, to_bytes, to_native
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.urls import open_url, ConnectionError, SSLValidationError


def assemble_json(cpmmodule, existing_interface):
    is_changed = 0
    json_load = ""
    ports = None
    web_trace = web_ocsp = web_term = web_timout = None
    web_httpenable = web_httpport = None
    web_httpsenable = web_httpsport = None
    web_harden = None
    web_tlsmode = None
    web_hsts = None
    private_filename = signed_filename = inter_filename = None
    file_error = False
    iSLength = 0

    if (cpmmodule.params['interface'] is not None):
        ports = to_native(cpmmodule.params['interface'])

    if (cpmmodule.params['trace'] is not None):
        web_trace = to_native(cpmmodule.params['trace'])

    if (cpmmodule.params['ocsp'] is not None):
        web_ocsp = to_native(cpmmodule.params['ocsp'])

    if (cpmmodule.params['timeout'] is not None):
        web_timeout = to_native(cpmmodule.params['timeout'])

    if (cpmmodule.params['webterm'] is not None):
        web_term = to_native(cpmmodule.params['webterm'])

    if (cpmmodule.params['httpenable'] is not None):
        web_httpenable = to_native(cpmmodule.params['httpenable'])

    if (cpmmodule.params['httpport'] is not None):
        web_httpport = to_native(cpmmodule.params['httpport'])

    if (cpmmodule.params['httpsenable'] is not None):
        web_httpsenable = to_native(cpmmodule.params['httpsenable'])

    if (cpmmodule.params['httpsport'] is not None):
        web_httpsport = to_native(cpmmodule.params['httpsport'])

    if (cpmmodule.params['harden'] is not None):
        web_harden = to_native(cpmmodule.params['harden'])

    if (cpmmodule.params['tlsmode'] is not None):
        web_tlsmode = to_native(cpmmodule.params['tlsmode'])

    if (cpmmodule.params['hsts'] is not None):
        web_hsts = to_native(cpmmodule.params['hsts'])

    if (cpmmodule.params['private_filename'] is not None):
        private_filename = to_native(cpmmodule.params['private_filename'])

    if (cpmmodule.params['signed_filename'] is not None):
        signed_filename = to_native(cpmmodule.params['signed_filename'])

    if (cpmmodule.params['inter_filename'] is not None):
        inter_filename = to_native(cpmmodule.params['inter_filename'])

    # Put the JSON request together
    if (web_trace is not None):
        if (existing_interface["trace"] != web_trace):
            is_changed = True
        json_load = '{"trace": %s' % (web_trace)
    else:
        json_load = '{"trace": "%s"' % (existing_interface["trace"])

    if (web_ocsp is not None):
        if (existing_interface["ocsp"] != web_ocsp):
            is_changed = True
        json_load = '%s, "ocsp": %s' % (json_load, web_ocsp)
    else:
        json_load = '%s,"ocsp": "%s"' % (json_load, existing_interface["ocsp"])

    if (web_timeout is not None):
        if (existing_interface["timeout"] != web_timeout):
            is_changed = True
        json_load = '%s, "timeout": %s' % (json_load, web_timeout)
    else:
        json_load = '%s,"timeout": "%s"' % (json_load, existing_interface["timeout"])

    if (web_term is not None):
        if (existing_interface["webterm"] != web_term):
            is_changed = True
        json_load = '%s, "webterm": %s' % (json_load, web_term)
    else:
        json_load = '%s,"webterm": "%s"' % (json_load, existing_interface["webterm"])

    if (ports is not None):
        json_load = '%s, "web": [{ "name":"%s"' % (json_load, ports)

        if (web_httpenable is not None):
            if (existing_interface["web"][0]["httpenable"] != web_httpenable):
                is_changed = True
            json_load = '%s, "httpenable": %s' % (json_load, web_httpenable)
        else:
            json_load = '%s,"httpenable": "%s"' % (json_load, existing_interface["web"][0]["httpenable"])

        if (web_httpport is not None):
            if (existing_interface["web"][0]["httpport"] != web_httpport):
                is_changed = True
            json_load = '%s, "httpport": %s' % (json_load, web_httpport)
        else:
            json_load = '%s,"httpport": "%s"' % (json_load, existing_interface["web"][0]["httpport"])

        if (web_httpsenable is not None):
            if (existing_interface["web"][0]["httpsenable"] != web_httpsenable):
                is_changed = True
            json_load = '%s, "httpsenable": %s' % (json_load, web_httpsenable)
        else:
            json_load = '%s,"httpsenable": "%s"' % (json_load, existing_interface["web"][0]["httpsenable"])

        if (web_httpsport is not None):
            if (existing_interface["web"][0]["httpsport"] != web_httpsport):
                is_changed = True
            json_load = '%s, "httpsport": %s' % (json_load, web_httpsport)
        else:
            json_load = '%s, "httpsport": "%s"' % (json_load, existing_interface["web"][0]["httpsport"])

        if (web_harden is not None):
            if (existing_interface["web"][0]["harden"] != web_harden):
                is_changed = True
            json_load = '%s, "harden": %s' % (json_load, web_harden)
        else:
            json_load = '%s, "harden": "%s"' % (json_load, existing_interface["web"][0]["harden"])

        if (web_tlsmode is not None):
            if (existing_interface["web"][0]["tlsmode"] != web_tlsmode):
                is_changed = True
            json_load = '%s, "tlsmode": %s' % (json_load, web_tlsmode)
        else:
            json_load = '%s, "tlsmode": "%s"' % (json_load, existing_interface["web"][0]["tlsmode"])

        if (web_hsts is not None):
            if (existing_interface["web"][0]["hsts"] != web_hsts):
                is_changed = True
            json_load = '%s, "hsts": %s' % (json_load, web_hsts)
        else:
            json_load = '%s, "hsts": "%s"' % (json_load, existing_interface["web"][0]["hsts"])

        try:
            if (private_filename is not None):
                with open(private_filename, 'r') as f:
                    private_filename = f.read()
                    f.close()

                    iSLength = len(private_filename)
                    private_filename = private_filename.replace("\r\n", "\\\\n")
                    if (iSLength == len(private_filename)):
                        private_filename = private_filename.replace("\r", "\\\\r")
                        private_filename = private_filename.replace("\n", "\\\\n")

                    if ((existing_interface["web"][0]["privkey"].replace("\\r", "") != private_filename) and
                       (existing_interface["web"][0]["privkey"].replace("\\n", "\\\\n") != private_filename)):
                        is_changed = True
                        json_load = '%s, "privkey": "%s"' % (json_load, private_filename)

            if (signed_filename is not None):
                with open(signed_filename, 'r') as f:
                    signed_filename = f.read()
                    f.close()

                    iSLength = len(signed_filename)
                    signed_filename = signed_filename.replace("\r\n", "\\\\n")
                    if (iSLength == len(signed_filename)):
                        signed_filename = signed_filename.replace("\r", "\\\\r")
                        signed_filename = signed_filename.replace("\n", "\\\\n")

                    if ((existing_interface["web"][0]["signkey"].replace("\\r", "") != signed_filename) and
                       (existing_interface["web"][0]["signkey"].replace("\\n", "\\\\n") != signed_filename)):
                        is_changed = True
                        json_load = '%s, "signkey": "%s"' % (json_load, signed_filename)

            if (cpmmodule.params['inter_filename'] is not None):
                with open(inter_filename, 'r') as f:
                    inter_filename = f.read()
                    f.close()
                    iSLength = len(inter_filename)
                    inter_filename = inter_filename.replace("\r\n", "\\\\n")
                    if (iSLength == len(inter_filename)):
                        inter_filename = inter_filename.replace("\r", "\\\\r")
                        inter_filename = inter_filename.replace("\n", "\\\\n")

                    try:
                        if ((existing_interface["web"][0]["interkey"].replace("\\r", "") != inter_filename) and
                           (existing_interface["web"][0]["interkey"].replace("\\n", "\\\\n") != inter_filename)):
                            is_changed = True
                            json_load = '%s, "interkey": "%s"' % (json_load, inter_filename)
                    except Exception as e:
                        is_changed = True
                        json_load = '%s, "interkey": "%s"' % (json_load, inter_filename)

        except IOError:
            file_error = True

    json_load = '%s}]}' % (json_load)

    return file_error, is_changed, json_load


def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        cpm_url=dict(type='str', required=True),
        cpm_username=dict(type='str', required=False),
        cpm_password=dict(type='str', required=True, no_log=True),
        interface=dict(type="str", required=True, choices=["eth0", "eth1", "ppp0", "qmimux0"]),
        trace=dict(type='int', required=False, default=None, choices=[0, 1]),
        ocsp=dict(type='int', required=False, default=None, choices=[0, 1]),
        timeout=dict(type='int', required=False, default=None),
        webterm=dict(type='int', required=False, default=None, choices=[0, 1]),
        httpenable=dict(type='int', required=False, choices=[0, 1]),
        httpport=dict(type='int', required=False),
        httpsenable=dict(type='int', required=False, choices=[0, 1]),
        httpsport=dict(type='int', required=False),
        harden=dict(type='int', required=False, choices=[0, 1, 2]),
        tlsmode=dict(type='int', required=False, choices=[0, 1, 2, 3]),
        hsts=dict(type='int', required=False, choices=[0, 1]),
        private_filename=dict(type='str', required=False),
        signed_filename=dict(type='str', required=False),
        inter_filename=dict(type='str', required=False),
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

    fullurl = ("%s%s/api/v2%s/config/web?ports=%s" % (transport, to_native(module.params['cpm_url']),
               "" if len(to_native(module.params['cpm_username'])) else "/token", to_native(module.params['interface'])))

    if (module.params['private_filename'] is not None) or (module.params['signed_filename'] is not None) or (module.params['inter_filename'] is not None):
        fullurl = ("%s&showcerts=yes" % (fullurl))

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

    was_changed = False
    file_err = False
    result['data'] = json.loads(response.read())
    file_err, was_changed, payload = assemble_json(module, result['data'])
    result['data'] = payload

    if file_err is True:
        result['data'] = json.loads('{"status": { "code": "101", "text": "One of the Certificate file locations defined in the playbook could not be read." }}')
        result['changed'] = False
    else:
        if module.check_mode:
            if (payload is not None) and (len(payload) > 0):
                result['changed'] = True
        else:
            if (payload is not None) and (len(payload) > 0):
                fullurl = ("%s%s/api/v2%s/config/web" % (transport, to_native(module.params['cpm_url']),
                           "" if len(to_native(module.params['cpm_username'])) else "/token"))
                method = 'POST'

                try:
                    response = open_url(fullurl, data=payload, method=method, validate_certs=module.params['validate_certs'],
                                        use_proxy=module.params['use_proxy'], headers=header)

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

                result['changed'] = was_changed
                result['data'] = json.loads(response.read())

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
