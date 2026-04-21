#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (C) 2023 Red Hat Inc.
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
# Module to retrieve WTI Network Web Parameters from WTI OOB and PDU devices.
# CPM remote_management
#
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: cpm_web_info
version_added: "2.10.0"
author:
    - "Western Telematic Inc. (@wtinetworkgear)"
short_description: Get network Web parameters from WTI OOB and PDU devices
description:
    - "Get network Web parameters from WTI OOB and PDU devices"
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
    interface:
        description:
            - This is the ethernet port name that is getting retrieved. It can include a single ethernet
            - port name, multiple ethernet port names separated by commas or not defined for all ports.
        required: false
        type: list
        elements: str
        choices:
            - eth0
            - eth1
            - ppp0
            - qmimux0
    include_certs:
        description:
            - If true, will return the Signed, Private and Intermediate Keys from the WTI device.
        type: bool
        required: false
        default: false
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
notes:
 - Use C(groups/cpm) in C(module_defaults) to set common options used between CPM modules.)
"""

EXAMPLES = """
- name: Get the network Web Parameters for all interfaces of a WTI device.
  cpm_web_info:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false

- name: Get the network Web Parameters for all interfaces of a WTI device using a User Token.
  cpm_web_info:
    cpm_url: "nonexist.wti.com"
    cpm_username: ""
    cpm_password: "randomusertokenfromthewtidevice"
    use_https: true
    validate_certs: false

- name: Get the network Web Parameters for eth0 of a WTI device, include the certificates in the response.
  cpm_web_info:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    include_certs: true
    use_https: false
    validate_certs: false
    interface: "eth0"
"""

RETURN = """
data:
  description: The output JSON returned from the commands sent
  returned: always
  type: complex
  contains:
    trace:
      description: Current state of TRACE requests for thw Web Server.
      returned: success
      type: int
      sample: 0
    ocsp:
      description: Current state of the Online Certificate Status Protocol (OCSP) for the Web Server.
      returned: success
      type: int
      sample: 1
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


def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        cpm_url=dict(type='str', required=True),
        cpm_username=dict(type='str', required=False),
        cpm_password=dict(type='str', required=True, no_log=True),
        interface=dict(type="list", elements="str", required=False, choices=["eth0", "eth1", "ppp0", "qmimux0"]),
        include_certs=dict(type='bool', default=False),
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
        protocol = "https://"
    else:
        protocol = "http://"

    fullurl = ("%s%s/api/v2%s/config/web" % (protocol, to_native(module.params['cpm_url']),
               "" if len(to_native(module.params['cpm_username'])) else "/token"))

    ports = module.params['interface']
    if (ports is not None):
        if isinstance(ports, list):
            ports = ','.join(to_native(x) for x in ports)
            fullurl = ("%s?ports=%s" % (fullurl, ports))

    if (module.params['include_certs'] is True):
        fullurl = ("%s%sshowcerts=yes" % (fullurl, "&" if (module.params['interface'] is not None) else "?"))

    try:
        response = open_url(fullurl, data=None, method='GET', validate_certs=module.params['validate_certs'], use_proxy=module.params['use_proxy'],
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

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
