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
# Module to retrieve WTI Power information from WTI OOB and PDU devices.
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
module: cpm_power_info
version_added: "2.9.0"
author:
    - "Western Telematic Inc. (@wtinetworkgear)"
short_description: Get the Power Information of a WTI device
description:
    - "Get the Power Information of a WTI device"
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
    cpm_startdate:
        description:
            - Start date of the range to look for power data
        type: str
        required: false
    cpm_enddate:
        description:
            - End date of the range to look for power data
        type: str
        required: false
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
- name: Get the Power Information of a WTI device
  cpm_power_info:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false

- name: Get the Power Information of a WTI device
  cpm_power_info:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: false
    validate_certs: false
    startdate: 01-12-2020"
    enddate: 02-16-2020"
"""

RETURN = """
data:
    description: The output JSON returned from the commands sent
    returned: always
    type: complex
    contains:
        timestamp:
            description: Current timestamp of the WTI device after module execution.
            returned: success
            type: str
            sample: "2020-02-24T20:54:03+00:00"
        powerunit:
            description: Identifies if the WTI device is a power type device.
            returned: success
            type: str
            sample: "1"
        outletmetering:
            description: Identifies if the WTI device has Poiwer Outlet metering.
            returned: success
            type: str
            sample: "1"
        ats:
            description: Identifies if the WTI device is an ATS type of power device.
            returned: success
            type: str
            sample: "1"
        plugcount:
            description: Current outlet plug count of the WTI device after module execution.
            returned: success
            type: str
            sample: "8"
        powerfactor:
            description: Power factor of the WTI device after module execution.
            returned: success
            type: str
            sample: "100"
        powereff:
            description: Power efficiency of the WTI device after module execution.
            returned: success
            type: str
            sample: "100"
        powerdatacount:
            description: Total powerdata samples returned after module execution.
            returned: success
            type: str
            sample: "1"
        powerdata:
            description: Power data of the WTI device after module execution.
            returned: success
            type: dict
            sample: [ { "timestamp": "2020-02-24T21:45:18+00:00",
                    "branch1": [{ "voltage1": "118.00","current1": "0.00","current2": "0.00","current3": "0.00","current4": "0.00",
                    "current5": "0.00","current6": "0.00","current7": "0.00","current8": "0.00"}] }]
        status:
            description: Return status after module completion
            returned: always
            type: dict
            sample: { "code": "0", "text": "OK" }
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
        cpm_username=dict(type='str', required=True),
        cpm_password=dict(type='str', required=True, no_log=True),
        cpm_startdate=dict(type='str', required=False),
        cpm_enddate=dict(type='str', required=False),
        use_https=dict(type='bool', default=True),
        validate_certs=dict(type='bool', default=True),
        use_proxy=dict(type='bool', default=False)
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

    additional = ""

    if module.params['cpm_startdate'] is not None and (len(to_native(module.params['cpm_startdate'])) > 0):
        if module.params['cpm_enddate'] is not None and (len(to_native(module.params['cpm_enddate'])) > 0):
            additional = "?startdate=%s&enddate=%s" % (to_native(module.params['cpm_startdate']), to_native(module.params['cpm_enddate']))

    fullurl = ("%s%s/api/v2/status/power" % (protocol, to_native(module.params['cpm_url'])))

    if (len(additional) > 0):
        fullurl += additional

    try:
        response = open_url(fullurl, data=None, method='GET', validate_certs=module.params['validate_certs'], use_proxy=module.params['use_proxy'],
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

    result['data'] = json.loads(response.read())

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
