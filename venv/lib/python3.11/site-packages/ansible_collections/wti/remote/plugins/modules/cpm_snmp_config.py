#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (C) 2019 Red Hat Inc.
# Copyright (C) 2020 Western Telematic Inc.
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
# Module to configure WTI network SNMP Parameters on WTI OOB and PDU devices.
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
module: cpm_snmp_config
version_added: "2.10.0"
author:
    - "Western Telematic Inc. (@wtinetworkgear)"
short_description: Set network IPTables parameters in WTI OOB and PDU devices
description:
    - "Set network IPTables parameters in WTI OOB and PDU devices"
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
            - The protocol that the SNMP entry should be applied. 0 = ipv4, 1 = ipv6.
        type: int
        required: false
        choices: [ 0, 1 ]
    enable:
        description:
            - The activates SNMP polling for the specified interface and protocol.
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
    readonly:
        description:
            - Controls the ability to change configuration parameters with SNMP.
        type: int
        required: false
        choices: [ 0, 1 ]
    version:
        description:
            - Defined which version of SNMP the device will respond to 0 = V1/V2 Only, 1 = V3 Only, 2 = V1/V2/V3.
        type: int
        required: false
        choices: [ 0, 1, 2 ]
    contact:
        description:
            - The name of the administrator responsible for SNMP issues.
        type: str
        required: false
    location:
        description:
            - The location of the SNMP Server.
        type: str
        required: false
    systemname:
        description:
            - The hostname of the WTI Device.
        type: str
        required: false
    rocommunity:
        description:
            - Read Only Community Password, not used for SNMP V3.
        type: str
        required: false
    rwcommunity:
        description:
            - Read/Write Community Password, not used for SNMP V3.
        type: str
        required: false
    clear:
        description:
            - Removes all the users for the protocol being defined before setting the newly defined entries.
        type: int
        required: false
        choices: [ 0, 1 ]
    index:
        description:
            - Index of the user being modified (V3 only).
        type: list
        elements: int
        required: false
    username:
        description:
            - Sets the User Name for SNMPv3 access (V3 only).
        type: list
        elements: str
        required: false
    authpriv:
        description:
            - Configures the Authentication and Privacy features for SNMPv3 communication, 0 = Auth/NoPriv, 1 = Auth/Priv (V3 only).
        type: list
        elements: int
        required: false
    authpass:
        description:
            - Sets the Authentication Password for SNMPv3 (V3 only).
        type: list
        elements: str
        required: false
    authproto:
        description:
            - Which authentication protocol will be used, 0 = MD5, 1 = SHA1 (V3 only).
        type: list
        elements: int
        required: false
    privpass:
        description:
            - Sets the Privacy Password for SNMPv3 (V3 only) (V3 only).
        type: list
        elements: str
        required: false
    privproto:
        description:
            - Which privacy protocol will be used, 0 = DES, 1 = AES128 (V3 only).
        type: list
        elements: int
        required: false
notes:
  - Use C(groups/cpm) in C(module_defaults) to set common options used between CPM modules.
"""

EXAMPLES = """
# Sets the device SNMP Parameters
- name: Set the an SNMP Parameter for a WTI device
  cpm_iptables_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    interface: "eth0"
    use_https: true
    validate_certs: false
    protocol: 0
    clear: 1
    enable: 1
    readonly: 0
    version: 0
    rocommunity: "ropassword"
    rwcommunity: "rwpassword"

# Sets the device SNMP Parameters
- name: Set the SNMP Parameters a WTI device
  cpm_iptables_config:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    use_https: true
    validate_certs: false
    version: 1
    index:
      - 1
      - 2
    username:
      - "username1"
      - "username2"
    authpriv:
      - 1
      - 1
    authpass:
      - "authpass1"
      - "uthpass2"
    authproto:
      - 1
      - 1
    privpass:
      - "authpass1"
      - "uthpass2"
    privproto:
      - 1
      - 1
"""

RETURN = """
data:
  description: The output JSON returned from the commands sent
  returned: always
  type: complex
  contains:
    snmpaccess:
      description: Current k/v pairs of interface info for the WTI device after module execution.
      returned: always
      type: dict
      sample: [{ "eth0": { "ietf-ipv4": { "clear": 1, "enable": 0, "readonly": 0, "version": 0, "users": [
              { "username": "username1", "authpass": "testpass", "authpriv": "1", "authproto": "0", "privpass": "privpass1",
                "privproto": "0", "index": "1" }]}}}]
"""

import base64
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text, to_bytes, to_native
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.urls import open_url, ConnectionError, SSLValidationError


def assemble_json(cpmmodule, existing_interface):
    total_username = total_indices = 0
    is_clear = is_changed = protocol = loop = 0
    json_load = ""
    ietfstring = "ietf-ipv4"
    snmpenable = snmpversion = snmpreadonly = None
    snmpsystemname = None
    snmpcontact = None
    snmplocation = None
    snmprocommunity = None
    snmprwcommunity = None
    user_load = ""

    indices = []
    usernamearray = []
    authpriv = []
    authpassarray = []
    authproto = []
    privpassarray = []
    privproto = []

    for x in range(0, 48):
        indices.insert(x, None)
        usernamearray.insert(x, None)
        authpriv.insert(x, None)
        authpassarray.insert(x, None)
        authproto.insert(x, None)
        privpassarray.insert(x, None)
        privproto.insert(x, None)

    ports = cpmmodule.params['interface']

    if (cpmmodule.params['clear'] is not None):
        is_clear = int(cpmmodule.params['clear'])

    if (cpmmodule.params['protocol'] is not None):
        protocol = int(cpmmodule.params['protocol'])
        if (protocol == 1):
            ietfstring = "ietf-ipv6"

    if (cpmmodule.params['enable'] is not None):
        snmpenable = int(cpmmodule.params['enable'])

    if (cpmmodule.params['version'] is not None):
        snmpversion = int(cpmmodule.params['version'])

    if (cpmmodule.params['readonly'] is not None):
        snmpreadonly = int(cpmmodule.params['readonly'])

    if (cpmmodule.params['systemname'] is not None):
        snmpsystemname = to_native(cpmmodule.params['systemname'])

    if (cpmmodule.params['contact'] is not None):
        snmpcontact = to_native(cpmmodule.params['contact'])

    if (cpmmodule.params['location'] is not None):
        snmplocation = to_native(cpmmodule.params['location'])

    if (cpmmodule.params['rocommunity'] is not None):
        snmprocommunity = to_native(cpmmodule.params['rocommunity'])

    if (cpmmodule.params['rwcommunity'] is not None):
        snmprwcommunity = to_native(cpmmodule.params['rwcommunity'])

    index = cpmmodule.params['index']
    if (index is not None):
        if isinstance(index, list):
            for x in index:
                indices.insert(total_indices, (int(to_native(x))) - 1)
                total_indices += 1

    ii = 0
    index = cpmmodule.params['authpriv']
    if (index is not None):
        if isinstance(index, list):
            for x in index:
                authpriv.insert(ii, int(to_native(x)))
                ii += 1

    ii = 0
    index = cpmmodule.params['authproto']
    if (index is not None):
        if isinstance(index, list):
            for x in index:
                authproto.insert(ii, int(to_native(x)))
                ii += 1

    ii = 0
    index = cpmmodule.params['privproto']
    if (index is not None):
        if isinstance(index, list):
            for x in index:
                privproto.insert(ii, int(to_native(x)))
                ii += 1

    total_username = 0
    usernamearray = cpmmodule.params['username']
    if (usernamearray is not None):
        if isinstance(usernamearray, list):
            for x in usernamearray:
                usernamearray[total_username] = to_native(x)
                total_username += 1

    ii = 0
    authpassarray = cpmmodule.params['authpass']
    if (authpassarray is not None):
        if isinstance(authpassarray, list):
            for x in authpassarray:
                authpassarray[ii] = to_native(x)
                ii += 1

    ii = 0
    authpassarray = cpmmodule.params['authpass']
    if (authpassarray is not None):
        if isinstance(authpassarray, list):
            for x in authpassarray:
                authpassarray[ii] = to_native(x)
                ii += 1

    ii = 0
    privpassarray = cpmmodule.params['privpass']
    if (privpassarray is not None):
        if isinstance(privpassarray, list):
            for x in privpassarray:
                privpassarray[ii] = to_native(x)
                ii += 1

    if (total_indices > 0):
        if (total_username != total_indices):
            return None

    for x in range(0, total_username):
        if (usernamearray[x] is not None):
            if (loop > 0):
                user_load = '%s,' % (user_load)

            user_load = '%s{"index": "%d"' % (user_load, (indices[x] + 1))

            if (usernamearray[x] is not None):
                if (existing_interface["snmpaccess"][ports][0][ietfstring]["users"][(indices[x])]["username"] != usernamearray[x]):
                    is_changed = True

                user_load = '%s,"username": "%s"' % (user_load, usernamearray[x])
            else:
                user_load = '%s,"username": "%s"' % (user_load, existing_interface["snmpaccess"][ports][0][ietfstring]["users"][(indices[x])]["username"])

            if (authpassarray[x] is not None):
                if (existing_interface["snmpaccess"][ports][0][ietfstring]["users"][(indices[x])]["authpass"] != authpassarray[x]):
                    is_changed = True
                user_load = '%s,"authpass": "%s"' % (user_load, authpassarray[x])
            else:
                user_load = '%s,"authpass": "%s"' % (user_load, existing_interface["snmpaccess"][ports][0][ietfstring]["users"][(indices[x])]["authpass"])

            if (privpassarray[x] is not None):
                if (existing_interface["snmpaccess"][ports][0][ietfstring]["users"][(indices[x])]["privpass"] != privpassarray[x]):
                    is_changed = True
                user_load = '%s,"privpass": "%s"' % (user_load, privpassarray[x])
            else:
                user_load = '%s,"privpass": "%s"' % (user_load, existing_interface["snmpaccess"][ports][0][ietfstring]["users"][(indices[x])]["privpass"])

            if (authpriv[x] is not None):
                if (int(existing_interface["snmpaccess"][ports][0][ietfstring]["users"][(indices[x])]["authpriv"]) != int(authpriv[x])):
                    is_changed = True
                user_load = '%s,"authpriv": "%s"' % (user_load, authpriv[x])
            else:
                user_load = '%s,"authpriv": "%s"' % (user_load, existing_interface["snmpaccess"][ports][0][ietfstring]["users"][(indices[x])]["authpriv"])

            if (authproto[x] is not None):
                if (int(existing_interface["snmpaccess"][ports][0][ietfstring]["users"][(indices[x])]["authproto"]) != int(authproto[x])):
                    is_changed = True
                user_load = '%s,"authproto": "%s"' % (user_load, authproto[x])
            else:
                user_load = '%s,"authproto": "%s"' % (user_load, existing_interface["snmpaccess"][ports][0][ietfstring]["users"][(indices[x])]["authproto"])

            if (privproto[x] is not None):
                if (int(existing_interface["snmpaccess"][ports][0][ietfstring]["users"][(indices[x])]["privproto"]) != int(privproto[x])):
                    is_changed = True
                user_load = '%s,"privproto": "%s"' % (user_load, privproto[x])
            else:
                user_load = '%s,"privproto": "%s"' % (user_load, existing_interface["snmpaccess"][ports][0][ietfstring]["users"][(indices[x])]["privproto"])

            user_load = '%s}' % (user_load)
            loop += 1

    if (loop > 0):
        json_load = '{"snmpaccess": [{"%s": { "%s": { "clear": %d, "change": %d' % (ports, ietfstring, is_clear, is_changed)

    if (snmpenable is not None):
        if (existing_interface["snmpaccess"][ports][0][ietfstring]["enable"] != snmpenable):
            is_changed = True
        json_load = '%s, "enable": %d' % (json_load, snmpenable)
    else:
        json_load = '%s,"enable": "%s"' % (json_load, existing_interface["snmpaccess"][ports][0][ietfstring]["enable"])

    if (snmpversion is not None):
        if (existing_interface["snmpaccess"][ports][0][ietfstring]["version"] != snmpversion):
            is_changed = True
        json_load = '%s, "version": %d' % (json_load, snmpversion)
    else:
        json_load = '%s,"version": "%s"' % (json_load, existing_interface["snmpaccess"][ports][0][ietfstring]["version"])

    if (snmpreadonly is not None):
        if (existing_interface["snmpaccess"][ports][0][ietfstring]["readonly"] != snmpreadonly):
            is_changed = True
        json_load = '%s, "readonly": %d' % (json_load, snmpreadonly)
    else:
        json_load = '%s,"readonly": "%s"' % (json_load, existing_interface["snmpaccess"][ports][0][ietfstring]["readonly"])

    if (snmpsystemname is not None):
        if (existing_interface["snmpaccess"][ports][0][ietfstring]["systemname"] != snmpsystemname):
            is_changed = True
        json_load = '%s, "systemname": %d' % (json_load, snmpsystemname)
    else:
        json_load = '%s,"systemname": "%s"' % (json_load, existing_interface["snmpaccess"][ports][0][ietfstring]["systemname"])

    if (snmpcontact is not None):
        if (existing_interface["snmpaccess"][ports][0][ietfstring]["contact"] != snmpcontact):
            is_changed = True
        json_load = '%s, "contact": %d' % (json_load, snmpcontact)
    else:
        json_load = '%s,"contact": "%s"' % (json_load, existing_interface["snmpaccess"][ports][0][ietfstring]["contact"])

    if (snmplocation is not None):
        if (existing_interface["snmpaccess"][ports][0][ietfstring]["location"] != snmplocation):
            is_changed = True
        json_load = '%s, "location": %d' % (json_load, snmplocation)
    else:
        json_load = '%s,"location": "%s"' % (json_load, existing_interface["snmpaccess"][ports][0][ietfstring]["location"])

    if (snmprocommunity is not None):
        if (existing_interface["snmpaccess"][ports][0][ietfstring]["rocommunity"] != snmprocommunity):
            is_changed = True
        json_load = '%s, "rocommunity": %d' % (json_load, snmprocommunity)
    else:
        json_load = '%s,"rocommunity": "%s"' % (json_load, existing_interface["snmpaccess"][ports][0][ietfstring]["rocommunity"])

    if (snmprwcommunity is not None):
        if (existing_interface["snmpaccess"][ports][0][ietfstring]["rwcommunity"] != snmprwcommunity):
            is_changed = True
        json_load = '%s, "rwcommunity": %d' % (json_load, snmprwcommunity)
    else:
        json_load = '%s,"rwcommunity": "%s"' % (json_load, existing_interface["snmpaccess"][ports][0][ietfstring]["rwcommunity"])

    if (len(user_load) > 0):
        json_load = '%s, "users": [ %s ]' % (json_load, user_load)

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
        version=dict(type='int', required=False, default=None, choices=[0, 1, 2]),
        readonly=dict(type='int', required=False, default=None, choices=[0, 1]),
        systemname=dict(type='str', required=False),
        contact=dict(type='str', required=False),
        location=dict(type='str', required=False),
        rocommunity=dict(type='str', required=False),
        rwcommunity=dict(type='str', required=False),
        index=dict(type='list', elements='int', required=False, default=None),
        username=dict(type='list', elements='str', required=False),
        authpriv=dict(type='list', elements='int', required=False, default=None),
        authproto=dict(type='list', elements='int', required=False, default=None),
        privproto=dict(type='list', elements='int', required=False, default=None),
        authpass=dict(type='list', elements='str', required=False, no_log=True),
        privpass=dict(type='list', elements='str', required=False, no_log=True),
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

    fullurl = ("%s%s/api/v2/config/snmpaccess?ports=%s" % (transport, to_native(module.params['cpm_url']), to_native(module.params['interface'])))
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
#    result['data'] = payload

    if module.check_mode:
        if (payload is not None) and (len(payload) > 0):
            result['changed'] = True
    else:
        if (payload is not None) and (len(payload) > 0):
            fullurl = ("%s%s/api/v2/config/snmpaccess" % (transport, to_native(module.params['cpm_url'])))
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
