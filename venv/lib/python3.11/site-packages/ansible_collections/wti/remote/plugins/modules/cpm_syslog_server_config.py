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
# Module to configure WTI network SYSLOG Server Parameters on WTI OOB and PDU devices.
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
module: cpm_syslog_server_config
version_added: "2.11.0"
author:
    - "Western Telematic Inc. (@wtinetworkgear)"
short_description: Set network SYSLOG Server parameters in WTI OOB and PDU devices
description:
    - "Set network SYSLOG Server parameters in WTI OOB and PDU devices"
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
    interface:
        description:
            - The ethernet port for the SYSLOG we are defining.
        type: str
        choices:
            - eth0
            - eth1
            - ppp0
            - qmimux0
        required: true
    protocol:
        description:
            - The protocol that the SYSLOG entry should be applied. 0 = ipv4, 1 = ipv6.
        type: int
        required: false
        choices: [ 0, 1 ]
    enable:
        description:
            - Activates SYSLOG listening for the specified interface and protocol.
        type: int
        required: false
        choices: [ 0, 1 ]
    port:
        description:
            - Defines the port number used by the SYSLOG Server (1 - 65535).
        type: int
        required: false
    transport:
        description:
            - Defines the transfer protocol type used by the SYSLOG Server. 0=UDP, 1=TCP;
        type: int
        required: false
        choices: [ 0, 1 ]
    secure:
        description:
            - Defines if a secure connection is used by the SYSLOG Server (TCP Transport required).
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
            - Sets the IP Address to block message logging.
        type: list
        elements: str
        required: false
notes:
  - Use C(groups/cpm) in C(module_defaults) to set common options used between CPM modules.
"""

EXAMPLES = """
# Sets the device SYSLOG Server Parameters
- name: Set the an SYSLOG Server Parameter for a WTI device
  cpm_iptables_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false
    interface: "eth0"
    protocol: 0
    port: 514
    transport: 0
    secure: 0
    clear: 1

# Sets the device SYSLOG Server Parameters
- name: Set the SYSLOG Server Parameters a WTI device
  cpm_iptables_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false
    interface: "eth0"
    protocol: 0
    port: 514
    transport: 0
    secure: 0
    clear: 1
    index:
      - 1
      - 2
    block:
      - "192.168.50.4"
      - "72.76.4.56"
"""

RETURN = """
data:
  description: The output JSON returned from the commands sent
  returned: always
  type: complex
  contains:
    syslogserver:
      description: Current k/v pairs of interface info for the WTI device after module execution.
      returned: always
      type: dict
      sample: {"syslogserver": { "eth0": [ {"ietf-ipv4": {
               "block": [{"address": "", "index": "1"}, {"address": "", "index": "2"},
               {"address": "", "index": "3"}, {"address": "", "index": "4"}],
               "enable": 0, "port": "514", "secure": "0", "transport": "0"},
              "ietf-ipv6": {
               "block": [{"address": "", "index": "1"}, {"address": "", "index": "2"},
               {"address": "", "index": "3"}, {"address": "", "index": "4"}],
               "enable": 0, "port": "514", "secure": "0", "transport": "0"}}]}}
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
    json_load = ""
    ietfstring = "ietf-ipv4"
    syslogenable = syslogport = syslogsecure = None
    syslogtransport = None
    user_load = ""

    indices = []
    blockarray = []

    for x in range(0, 48):
        indices.insert(x, None)
        blockarray.insert(x, None)

    ports = cpmmodule.params['interface']

    if (cpmmodule.params['clear'] is not None):
        is_clear = int(cpmmodule.params['clear'])

    if (cpmmodule.params['protocol'] is not None):
        protocol = int(cpmmodule.params['protocol'])
        if (protocol == 1):
            ietfstring = "ietf-ipv6"

    if (cpmmodule.params['enable'] is not None):
        syslogenable = int(cpmmodule.params['enable'])

    if (cpmmodule.params['port'] is not None):
        syslogport = int(cpmmodule.params['port'])

    if (cpmmodule.params['transport'] is not None):
        syslogtransport = int(cpmmodule.params['transport'])

    if (cpmmodule.params['secure'] is not None):
        syslogsecure = int(cpmmodule.params['secure'])

    index = cpmmodule.params['index']
    if (index is not None):
        if isinstance(index, list):
            for x in index:
                indices.insert(total_indices, (int(to_native(x))) - 1)
                total_indices += 1

    total_block = 0
    blockarray = cpmmodule.params['address']
    if (blockarray is not None):
        if isinstance(blockarray, list):
            for x in blockarray:
                blockarray[total_block] = to_native(x)
                total_block += 1

    if (total_indices > 0):
        if (total_block != total_indices):
            return is_changed, None

    for x in range(0, total_block):
        if (blockarray[x] is not None):
            if (loop > 0):
                user_load = '%s,' % (user_load)

            user_load = '%s{"index": "%d"' % (user_load, (indices[x] + 1))

            if (blockarray[x] is not None):
                if (existing_interface["syslogserver"][ports][0][ietfstring]["block"][(indices[x])]["address"] != blockarray[x]):
                    is_changed = True

                user_load = '%s,"address": "%s"' % (user_load, blockarray[x])
            else:
                user_load = '%s,"address": "%s"' % (user_load, existing_interface["syslogserver"][ports][0][ietfstring]["block"][(indices[x])]["address"])

            user_load = '%s}' % (user_load)
            loop += 1

    json_load = '{"syslogserver": [{"%s": { "%s": { "clear": %d, "change": %d' % (ports, ietfstring, is_clear, is_changed)

    if (syslogenable is not None):
        if (int(existing_interface["syslogserver"][ports][0][ietfstring]["enable"]) != syslogenable):
            is_changed = True
        json_load = '%s, "enable": %d' % (json_load, syslogenable)
    else:
        json_load = '%s,"enable": "%s"' % (json_load, existing_interface["syslogserver"][ports][0][ietfstring]["enable"])

    if (syslogport is not None):
        if (int(existing_interface["syslogserver"][ports][0][ietfstring]["port"]) != syslogport):
            is_changed = True
        json_load = '%s, "port": %d' % (json_load, syslogport)
    else:
        json_load = '%s,"port": "%s"' % (json_load, existing_interface["syslogserver"][ports][0][ietfstring]["port"])

    if (syslogtransport is not None):
        if (int(existing_interface["syslogserver"][ports][0][ietfstring]["transport"]) != syslogtransport):
            is_changed = True
        json_load = '%s, "transport": %d' % (json_load, syslogtransport)
    else:
        json_load = '%s,"transport": "%s"' % (json_load, existing_interface["syslogserver"][ports][0][ietfstring]["transport"])

    if (syslogsecure is not None):
        if (int(existing_interface["syslogserver"][ports][0][ietfstring]["secure"]) != syslogsecure):
            is_changed = True
        json_load = '%s, "secure": %d' % (json_load, syslogsecure)
    else:
        json_load = '%s,"secure": "%s"' % (json_load, existing_interface["syslogserver"][ports][0][ietfstring]["secure"])

    if (len(user_load) > 0):
        json_load = '%s, "block": [ %s ]' % (json_load, user_load)

    json_load = '%s}}}]}' % (json_load)

    return is_changed, json_load


def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        cpm_url=dict(type='str', required=True),
        cpm_username=dict(type='str', required=True),
        cpm_password=dict(type='str', required=True, no_log=True),
        interface=dict(type="str", required=True, choices=["eth0", "eth1", "ppp0", "qmimux0"]),
        protocol=dict(type='int', required=False, default=None, choices=[0, 1]),
        clear=dict(type='int', required=False, default=None, choices=[0, 1]),
        enable=dict(type='int', required=False, default=None, choices=[0, 1]),
        port=dict(type='int', required=False, default=None),
        transport=dict(type='int', required=False, default=None, choices=[0, 1]),
        secure=dict(type='int', required=False, choices=[0, 1]),
        index=dict(type='list', elements='int', required=False, default=None),
        address=dict(type='list', elements='str', required=False),
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

    fullurl = ("%s%s/api/v2/config/syslogserver?ports=%s" % (transport, to_native(module.params['cpm_url']), to_native(module.params['interface'])))
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
#   result['data'] = payload

    if module.check_mode:
        if (payload is not None) and (len(payload) > 0):
            result['changed'] = True
    else:
        if (payload is not None) and (len(payload) > 0):
            fullurl = ("%s%s/api/v2/config/syslogserver" % (transport, to_native(module.params['cpm_url'])))
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

            result['changed'] = was_changed
            result['data'] = json.loads(response.read())

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
