#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (C) 2019 Red Hat Inc.
# Copyright (C) 2021 Western Telematic Inc.
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
# Module to execute WTI hostname parameters from WTI OOB and PDU devices.
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
module: cpm_hostname_config
version_added: "2.11.0"
author:
    - "Western Telematic Inc. (@wtinetworkgear)"
short_description: Set Hostname (Site ID), Location, Asset Tag parameters in WTI OOB and PDU devices.
description:
    - "Set Hostname (Site ID), Location, Asset Tag parameters parameters in WTI OOB and PDU devices"
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
    siteid:
        description:
            - This is the Site ID to be set for the WTI OOB and PDU device.
        type: str
        required: false
    location:
        description:
            - This is the Location to be set for the WTI OOB and PDU device.
        type: str
        required: false
    hostname:
        description:
            - This is the Hostname to be set for the WTI OOB and PDU device.
        type: str
        required: false
    domain:
        description:
            - This is the Domain to be set for the WTI OOB and PDU device.
        type: str
        required: false
    assettag:
        description:
            - This is the Asset Tag to be set for the WTI OOB and PDU device.
        type: str
        required: false
notes:
  - Use C(groups/cpm) in C(module_defaults) to set common options used between CPM modules.
"""

EXAMPLES = """
# Set Hostname, Location and Site-ID variables of a WTI device
- name: Set known fixed hostname variables of a WTI device
  cpm_time_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false
    siteid: "DSMLABIRVINE"
    location: "RACK12IRVINE"
    hostname: "myhostname"
    domain: "mydomain.com"
    assettag: "irvine92395"

# Set the Hostname variable of a WTI device
- name: Set the Hostname of a WTI device
  cpm_time_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false
    hostname: "myhostname"
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
      sample: "2021-08-17T21:33:50+00:00"
    siteid:
      description: Current Site ID of the WTI device.
      returned: success
      type: str
      sample: "DSMLABIRVINE"
    location:
      description: Current Location of the WTI device.
      returned: success
      type: str
      sample: "RACK12IRVINE"
    hostname:
      description: Current Hostname of the WTI device.
      returned: success
      type: str
      sample: "myhostname"
    domain:
      description: Current Domain of the WTI device.
      returned: success
      type: str
      sample: "mydomain.com"
    assettag:
      description: Current Asset Tag of the WTI device.
      returned: success
      type: str
      sample: "irvine92395"
"""

import base64
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text, to_bytes, to_native
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.urls import open_url, ConnectionError, SSLValidationError


def assemble_json(cpmmodule, existing):
    total_change = 0
    json_load = ietfstring = ""

    localsiteid = locallocation = localhostname = localdomain = localassettag = None

    if cpmmodule.params["siteid"] is not None:
        if (existing["unitid"]["siteid"] != to_native(cpmmodule.params["siteid"])):
            total_change = (total_change | 8)
            localsiteid = to_native(cpmmodule.params["siteid"])
    if cpmmodule.params["location"] is not None:
        if (existing["unitid"]["location"] != to_native(cpmmodule.params["location"])):
            total_change = (total_change | 2)
            locallocation = to_native(cpmmodule.params["location"])
    if cpmmodule.params["hostname"] is not None:
        if (existing["unitid"]["hostname"] != to_native(cpmmodule.params["hostname"])):
            total_change = (total_change | 1)
            localhostname = to_native(cpmmodule.params["hostname"])
    if cpmmodule.params["domain"] is not None:
        if (existing["unitid"]["domain"] != to_native(cpmmodule.params["domain"])):
            total_change = (total_change | 16)
            localdomain = to_native(cpmmodule.params["domain"])
    if cpmmodule.params["assettag"] is not None:
        if (existing["unitid"]["assettag"] != to_native(cpmmodule.params["assettag"])):
            total_change = (total_change | 4)
            localassettag = to_native(cpmmodule.params["assettag"])

    if (total_change > 0):
        protocol = protocolchanged = 0
        ietfstring = ""

        if (localsiteid is not None):
            ietfstring = '%s"siteid": "%s"' % (ietfstring, localsiteid)

        if (locallocation is not None):
            if (len(ietfstring) > 0):
                ietfstring = '%s,' % (ietfstring)
            ietfstring = '%s"location": "%s"' % (ietfstring, locallocation)

        if (localhostname is not None):
            if (len(ietfstring) > 0):
                ietfstring = '%s,' % (ietfstring)
            ietfstring = '%s"hostname": "%s"' % (ietfstring, localhostname)

        if (localdomain is not None):
            if (len(ietfstring) > 0):
                ietfstring = '%s,' % (ietfstring)
            ietfstring = '%s"domain": "%s"' % (ietfstring, localdomain)

        if (localassettag is not None):
            if (len(ietfstring) > 0):
                ietfstring = '%s,' % (ietfstring)
            ietfstring = '%s"assettag": "%s"' % (ietfstring, localassettag)

        json_load = '{"unitid": {'
        json_load = '%s%s' % (json_load, ietfstring)
        json_load = '%s}}' % (json_load)
    else:
        json_load = None
    return json_load


def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        cpm_url=dict(type='str', required=True),
        cpm_username=dict(type='str', required=True),
        cpm_password=dict(type='str', required=True, no_log=True),
        siteid=dict(type='str', required=False, default=None),
        location=dict(type='str', required=False, default=None),
        hostname=dict(type='str', required=False, default=None),
        domain=dict(type='str', required=False, default=None),
        assettag=dict(type='str', required=False, default=None),
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

    fullurl = ("%s%s/api/v2/config/hostname" % (protocol, to_native(module.params['cpm_url'])))
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

    result['data'] = response.read()
    payload = assemble_json(module, json.loads(result['data']))

    if module.check_mode:
        if payload is not None:
            result['changed'] = True
    else:
        if payload is not None:
            fullurl = ("%s%s/api/v2/config/hostname" % (protocol, to_native(module.params['cpm_url'])))
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
