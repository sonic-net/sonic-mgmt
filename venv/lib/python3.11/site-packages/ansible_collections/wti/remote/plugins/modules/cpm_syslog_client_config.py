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
# Module to configure WTI network SYSLOG Client Parameters on WTI OOB and PDU devices.
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
module: cpm_syslog_client_config
version_added: "2.11.0"
author:
    - "Western Telematic Inc. (@wtinetworkgear)"
short_description: Set network SYSLOG Client parameters in WTI OOB and PDU devices
description:
    - "Set network SYSLOG Client parameters in WTI OOB and PDU devices"
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
    protocol:
        description:
            - The protocol that the SYSLOG entry should be applied. 0 = ipv4, 1 = ipv6.
        type: int
        required: false
        choices: [ 0, 1 ]
    clear:
        description:
            - Removes all the IP block entries for the protocol being defined before setting the newly defined entries.
        type: int
        required: false
        choices: [ 0, 1 ]
    index:
        description:
            - Index of the IP block being modified.
        type: list
        elements: int
        required: false
    address:
        description:
            - Sets the IP Address of the SYSLOG server to contact.
        type: list
        elements: str
        required: false
    port:
        description:
            - Defines the port number used by the SYSLOG Client (1 - 65535).
        type: list
        elements: int
        required: false
    transport:
        description:
            - Defines the transfer protocol type used by the SYSLOG Client. 0=UDP, 1=TCP;
        type: list
        elements: int
        required: false
    secure:
        description:
            - Defines if a secure connection is used by the SYSLOG Client (TCP Transport required).
        type: list
        elements: int
        required: false

notes:
  - Use C(groups/cpm) in C(module_defaults) to set common options used between CPM modules.
"""

EXAMPLES = """
# Sets the device SYSLOG Client Parameters
- name: Set the an SYSLOG Client Parameter for a WTI device
  cpm_iptables_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false
    protocol: 0
    index:
      - 1
    address:
      - "11.22.33.44"
    port:
      - 555
    transport:
      - 1
    secure:
      - 0

# Sets the device SYSLOG Client Parameters
- name: Set the SYSLOG Client Parameters a WTI device
  cpm_iptables_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false
    protocol: 0
    index:
      - 1
      - 2
    address:
      - "11.22.33.44"
      - "55.66.77.88"
    port:
      - 555
      - 557
    transport:
      - 1
      - 0
    secure:
      - 0
      - 1
"""

RETURN = """
data:
  description: The output JSON returned from the commands sent
  returned: always
  type: complex
  contains:
    syslogclient:
      description: Current k/v pairs of interface info for the WTI device after module execution.
      returned: always
      type: dict
      sample: {"syslogclient": {
               "ietf-ipv4": {
                "clients": [
                 {"address": "", "port": "514", "transport": "0", "secure": "0", "index": "1"},
                 {"address": "", "port": "514", "transport": "0", "secure": "0", "index": "2"},
                 {"address": "", "port": "514", "transport": "0", "secure": "0", "index": "3"},
                 {"address": "", "port": "514", "transport": "0", "secure": "0", "index": "4"}]},
               "ietf-ipv6": {
                "clients": [
                 {"address": "", "port": "514", "transport": "0", "secure": "0", "index": "1"},
                 {"address": "", "port": "514", "transport": "0", "secure": "0", "index": "2"},
                 {"address": "", "port": "514", "transport": "0", "secure": "0", "index": "3"},
                 {"address": "", "port": "514", "transport": "0", "secure": "0", "index": "4"}]}}}
"""

import base64
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text, to_bytes, to_native
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.urls import open_url, ConnectionError, SSLValidationError


def assemble_json(cpmmodule, existing_interface):
    total_block = total_indices = 0
    is_clear = is_changed = protocol = loop = 0
    json_load = user_load = ""
    ietfstring = "ietf-ipv4"
    syslogaddress = syslogenable = syslogport = syslogsecure = None
    syslogtransport = None

    indices = []
    addressarray = []
    portarray = []
    transportarray = []
    securearray = []

    for x in range(0, 5):
        indices.insert(x, None)
        addressarray.insert(x, None)
        portarray.insert(x, None)
        transportarray.insert(x, None)
        securearray.insert(x, None)

    if (cpmmodule.params['clear'] is not None):
        is_clear = int(cpmmodule.params['clear'])

    if (cpmmodule.params['protocol'] is not None):
        protocol = int(cpmmodule.params['protocol'])
        if (protocol == 1):
            ietfstring = "ietf-ipv6"

    index = cpmmodule.params['index']
    if (index is not None):
        if isinstance(index, list):
            for x in index:
                indices.insert(total_indices, (int(to_native(x))) - 1)
                total_indices += 1

    # read in the list of syslog client addresses
    total_block = 0
    syslogaddress = cpmmodule.params['address']
    if (syslogaddress is not None):
        if isinstance(syslogaddress, list):
            for x in syslogaddress:
                addressarray[total_block] = to_native(x)
                total_block += 1

    # the number of idicies and addresses must match
    if (total_indices > 0):
        if (total_block != total_indices):
            return is_changed, None

    # read in the list of syslog client ports
    total_block = 0
    syslogport = cpmmodule.params['port']
    if (syslogport is not None):
        if isinstance(syslogport, list):
            for x in syslogport:
                portarray[total_block] = (int(to_native(x)))
                total_block += 1

    if (total_block > 0):
        if (total_block != total_indices):
            return is_changed, None

    # read in the list of syslog client transport protocols
    total_block = 0
    syslogtransport = cpmmodule.params['transport']
    if (syslogtransport is not None):
        if isinstance(syslogtransport, list):
            for x in syslogtransport:
                transportarray[total_block] = (int(to_native(x)))
                total_block += 1

    if (total_block > 0):
        if (total_block != total_indices):
            return is_changed, None

    # read in the list of syslog client secure enable
    total_block = 0
    syslogsecure = cpmmodule.params['secure']
    if (syslogsecure is not None):
        if isinstance(syslogsecure, list):
            for x in syslogsecure:
                securearray[total_block] = (int(to_native(x)))
                total_block += 1

    if (total_block > 0):
        if (total_block != total_indices):
            return is_changed, None

    for x in range(0, total_indices):
        if (addressarray[x] is not None):
            if (loop > 0):
                user_load = '%s,' % (user_load)

            user_load = '%s{"index": "%d"' % (user_load, (indices[x] + 1))

            if (addressarray[x] is not None):
                if (existing_interface["syslogclient"][ietfstring]["clients"][(indices[x])]["address"] != addressarray[x]):
                    is_changed = True

                user_load = '%s,"address": "%s"' % (user_load, addressarray[x])
            else:
                user_load = '%s,"address": "%s"' % (user_load, existing_interface["syslogclient"][ietfstring]["clients"][(indices[x])]["address"])

            # see if the port number was changed
            if (portarray[x] is not None):
                if (int(existing_interface["syslogclient"][ietfstring]["clients"][(indices[x])]["port"]) != portarray[x]):
                    is_changed = True

                user_load = '%s,"port": "%s"' % (user_load, portarray[x])
            else:
                user_load = '%s,"port": "%s"' % (user_load, existing_interface["syslogclient"][ietfstring]["clients"][(indices[x])]["port"])

            # see if the transport type was changed
            if (transportarray[x] is not None):
                if (int(existing_interface["syslogclient"][ietfstring]["clients"][(indices[x])]["transport"]) != transportarray[x]):
                    is_changed = True

                user_load = '%s,"transport": "%s"' % (user_load, transportarray[x])
            else:
                user_load = '%s,"transport": "%s"' % (user_load, existing_interface["syslogclient"][ietfstring]["clients"][(indices[x])]["transport"])

            # see if the secure choice was changed
            if (securearray[x] is not None):
                if (int(existing_interface["syslogclient"][ietfstring]["clients"][(indices[x])]["secure"]) != securearray[x]):
                    is_changed = True

                user_load = '%s,"secure": "%s"' % (user_load, securearray[x])
            else:
                user_load = '%s,"secure": "%s"' % (user_load, existing_interface["syslogclient"][ietfstring]["clients"][(indices[x])]["secure"])

            user_load = '%s}' % (user_load)
            loop += 1

    json_load = '{"syslogclient": [{ "%s": { "clear": %d, "change": %d' % (ietfstring, is_clear, is_changed)

    if (len(user_load) > 0):
        json_load = '%s, "clients": [ %s ]' % (json_load, user_load)

    json_load = '%s}}]}' % (json_load)

    return is_changed, json_load


def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        cpm_url=dict(type='str', required=True),
        cpm_username=dict(type='str', required=True),
        cpm_password=dict(type='str', required=True, no_log=True),
        protocol=dict(type='int', required=False, default=None, choices=[0, 1]),
        clear=dict(type='int', required=False, default=None, choices=[0, 1]),
        index=dict(type='list', elements='int', required=False, default=None),
        address=dict(type='list', elements='str', required=False),
        port=dict(type='list', elements='int', required=False),
        transport=dict(type='list', elements='int', required=False),
        secure=dict(type='list', elements='int', required=False),
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
        transport = "https://"
    else:
        transport = "http://"

    fullurl = ("%s%s/api/v2/config/syslogclient" % (transport, to_native(module.params['cpm_url'])))
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

    was_changed = False
    result['data'] = json.loads(response.read())
    was_changed, payload = assemble_json(module, result['data'])

    if module.check_mode:
        if (payload is not None) and (len(payload) > 0):
            result['changed'] = True
    else:
        if (payload is not None) and (len(payload) > 0):
            fullurl = ("%s%s/api/v2/config/syslogclient" % (transport, to_native(module.params['cpm_url'])))
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

            result['data'] = response.read()
        else:
            result['data'] = json.loads('{"status": {"code": "-1", "text": "error with JSON and/or variables assembly"}}')

        result['changed'] = was_changed

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
