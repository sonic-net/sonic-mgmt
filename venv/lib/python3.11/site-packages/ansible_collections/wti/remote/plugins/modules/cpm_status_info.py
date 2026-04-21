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
# Module to retrieve WTI general status information from WTI OOB and PDU devices.
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
module: cpm_status_info
version_added: "2.9.0"
author:
    - "Western Telematic Inc. (@wtinetworkgear)"
short_description: Get general status information from WTI OOB and PDU devices
description:
    - "Get temperature general status from WTI OOB and PDU devices"
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
        description:
            - Flag to control if the lookup will observe HTTP proxy environment variables when present.
        type: bool
        required: false
        default: false
notes:
 - Use C(groups/cpm) in C(module_defaults) to set common options used between CPM modules.)
"""

EXAMPLES = """
- name: Get the Status Information for a WTI device
  cpm_status_info:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false

- name: Get the Status Information for a WTI device
  cpm_status_info:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: false
    validate_certs: false
"""

RETURN = """
data:
    description: The output JSON returned from the commands sent
    returned: always
    type: complex
    contains:
        vendor:
            description: Identifies WTI device as a WTI device.
            returned: success
            type: str
            sample: "wti"
        product:
            description: Current Product Part Number of the WTI device.
            returned: success
            type: str
            sample: "CPM-800-1-CA"
        totalports:
            description: Total serial ports of the WTI device.
            returned: success
            type: str
            sample: "9"
        totalplugs:
            description: Total Power Outlet plugs of the WTI device.
            returned: success
            type: str
            sample: "8"
        option1/2:
            description: Various Identity options of the WTI.
            returned: success
            type: str
            sample: "WPO-STRT-CPM8 / W4G-VZW-CPM8"
        softwareversion:
            description: Expanded Firmware version of the WTI device.
            returned: success
            type: str
            sample: "6.60 19 Feb 2020"
        serialnumber:
            description: Current Serial number of the WTI device.
            returned: success
            type: str
            sample: "12345678901234"
        assettag:
            description: Current Asset Tag of the WTI device.
            returned: success
            type: str
            sample: "ARTE121"
        siteid:
            description: Current Site-ID of the WTI device.
            returned: success
            type: str
            sample: "GENEVARACK"
        analogmodemphonenumber:
            description: Current Analog Modem (if installed) Phone number of the WTI device.
            returned: success
            type: str
            sample: "9495869959"
        modeminstalled:
            description: Identifies if a modem is installed in the WTI device.
            returned: success
            type: str
            sample: "Yes, 4G/LTE"
        modemmodel:
            description: Identifies the modem model number (if installed) in the WTI device.
            returned: success
            type: str
            sample: "MTSMC-LVW2"
        gig_dualphy:
            description: Identifies dual ethernet port and gigabyte ethernet ports in the WTI device.
            returned: success
            type: str
            sample: "Yes, Yes"
        cpu_boardprogramdate:
            description: Current Board and Program date of the WTI device.
            returned: success
            type: str
            sample: "ARM, 4-30-2019"
        ram_flash:
            description: Total RAM and FLASH installed in the WTI device..
            returned: success
            type: str
            sample: "512 MB, 128 MB"
        lineinputcount_rating:
            description: Identifies total power inlets and their power rating.
            returned: success
            type: str
            sample: "1 ,  20 Amps"
        currentmonitor:
            description: Identifies if the unit has current monitoring capabilites.
            returned: success
            type: str
            sample: "Yes"
        keylength:
            description: Current key length of the WTI device.
            returned: success
            type: str
            sample: "2048"
        opensslversion:
            description: Current OpenSSL version running on the WTI device.
            returned: success
            type: str
            sample: "1.1.1d  10 Sep 2019"
        opensshversion:
            description: Current OpenSSH running on the WTI device.
            returned: success
            type: str
            sample: "8.2p1"
        apacheversion:
            description: Current Apache Web version running on the WTI device.
            returned: success
            type: str
            sample: "2.4.41"
        apirelease:
            description: Current Date of the API release of the WTI device.
            returned: success
            type: str
            sample: "March 2020"
        uptime:
            description: Current uptime of the WTI device.
            returned: success
            type: str
            sample: "259308.26"
        energywise:
            description: Current Energywise version of the WTI device.
            returned: success
            type: str
            sample: "1.2.0"
        restful:
            description: Current RESTful version of the WTI device.
            returned: success
            type: str
            sample: "v1.0, v2 (Mar20)"
        interface_list:
            description: Current ethernet ports of the WTI device.
            returned: success
            type: str
            sample: "eth0"
        macaddresses:
            description: Current mac addresses of the WTI device.
            returned: always
            type: dict
            sample: { "mac": "00-09-9b-02-9a-26" }
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

    fullurl = ("%s%s/api/v2/status/status" % (protocol, to_native(module.params['cpm_url'])))

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
