#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_json_generic
short_description: Config Fortinet's FortiOS and FortiGate with json generic method.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify json feature and generic category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.4
version_added: "2.0.0"
author:
    - Frank Shen (@frankshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Requires fortiosapi library developed by Fortinet
    - Run as a local_action in your playbook
requirements:
    - fortiosapi>=0.9.8
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    json_generic:
        description:
            - json generic
        default: null
        type: dict
        suboptions:
            dictbody:
                description:
                    - Body with YAML list of key/value format
                type: dict
            jsonbody:
                description:
                    - Body with JSON string format, will always give priority to jsonbody
                type: str
            method:
                description:
                    - HTTP methods
                type: str
                required: true
                choices:
                    - 'GET'
                    - 'PUT'
                    - 'POST'
                    - 'DELETE'
            path:
                description:
                    - URL path, e.g./api/v2/cmdb/firewall/address
                type: str
                required: true
            specialparams:
                description:
                    - Extra URL parameters, e.g.start=1&count=10
                type: str
'''

EXAMPLES = '''
- name: add firewall address
  fortinet.fortios.fortios_json_generic:
      vdom: "root"
      json_generic:
          method: "POST"
          path: "/api/v2/cmdb/firewall/address"
          jsonbody: |
              {
                  "name": "111",
                  "type": "geography",
                  "fqdn": "",
                  "country": "AL",
                  "comment": "ccc",
                  "visibility": "enable",
                  "associated-interface": "port1",
                  "allow-routing": "disable"
              }
  register: info

- name: display vars
  debug: msg="{{info}}"

- name: delete firewall address
  fortinet.fortios.fortios_json_generic:
      vdom: "root"
      json_generic:
          method: "DELETE"
          path: "/api/v2/cmdb/firewall/address/111"
  register: info

- name: display vars
  debug: msg="{{info}}"

- name: test add with dict
  fortinet.fortios.fortios_json_generic:
      vdom: "root"
      json_generic:
          method: "POST"
          path: "/api/v2/cmdb/firewall/address"
          dictbody:
              name: "111"
              type: "geography"
              fqdn: ""
              country: "AL"
              comment: "it's a test"
              visibility: "enable"
              associated-interface: "port1"
              allow-routing: "disable"
  register: info

- name: display vars
  debug: msg="{{info}}"

- name: test speical params
  fortinet.fortios.fortios_json_generic:
      vdom: "root"
      json_generic:
          method: "PUT"
          path: "/api/v2/cmdb/firewall/policy/1"
          specialparams: "action=move&after=2"
  register: info

- name: display vars
  debug: msg="{{info}}"
'''

RETURN = '''
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"

'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import FortiOSHandler
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import check_legacy_fortiosapi

import json


def login(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    ssl_verify = data['ssl_verify']

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password, verify=ssl_verify)


def json_generic(data, fos):
    vdom = data['vdom']
    json_generic_data = data['json_generic']

    # Give priority to jsonbody
    data = ""
    if json_generic_data['jsonbody']:
        try:
            data = json.loads(json_generic_data['jsonbody'])
        except Exception as e:
            fos._module.fail_json("invalid json content: %s" % (e))
    else:
        if json_generic_data['dictbody']:
            data = json_generic_data['dictbody']

    return fos.jsonraw(json_generic_data['method'],
                       json_generic_data['path'],
                       data=data,
                       specific_params=json_generic_data['specialparams'],
                       vdom=vdom)


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' \
        or 'http_method' in resp and resp['http_method'] == 'DELETE' \
        and 'http_status' in resp and resp['http_status'] == 404


def fortios_json(data, fos):

    if data['json_generic']:
        resp = json_generic(data, fos)

    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": 'bool', "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "json_generic": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "dictbody": {"required": False, "type": "dict"},
                "jsonbody": {"required": False, "type": "str"},
                "method": {"required": True, "type": "str",
                           "choices": ["GET", "PUT", "POST",
                                       "DELETE"]},
                "path": {"required": True, "type": "str"},
                "specialparams": {"required": False, "type": "str"}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None

    if module._socket_path:
        connection = Connection(module._socket_path)
        if 'access_token' in module.params:
            connection.set_custom_option('access_token', module.params['access_token'])
        if 'enable_log' in module.params:
            connection.set_custom_option('enable_log', module.params['enable_log'])
        else:
            connection.set_custom_option('enable_log', False)
        fos = FortiOSHandler(connection, module)
        is_error, has_changed, result = fortios_json(module.params, fos)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Unable to precess the request, please provide correct parameters and make sure the path exists.", meta=result)


if __name__ == '__main__':
    main()
