#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright 2019-2021 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fmgr_generic
short_description: Build and send generic FortiManager API request.
description:
    - This module is for generic fortimanager requests. it receives raw json-rpc
      data, and sends it to fortimanager, finally returns the response to users.
    - This module also rely on fortimanager httpapi plugin as the transport.
    - the payload doesn't include session, the httpapi plugin will automatically
      fill the session later.
    - the username and password is not managed by the module, but by the plugin.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Link Zheng (@zhengl)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - two parameters schemes are supported, either in raw json format or in
      ansible recognnizable top-level parameters format.
    - json is defined as string, user is response for make it json-formatted
    - method and params should be specified by users if 'json' is not present
    - if all three parameters are provided, the 'json' is preferred.
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        required: false
        type: str
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: authenticate Ansible client with forticloud API access token
        required: false
        type: str
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
        elements: int
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        elements: int
        required: false
    workspace_locking_adom:
        description: no description
        type: str
        required: false
    workspace_locking_timeout:
        description: no description
        type: int
        required: false
        default: 300
    method:
        description:
            - the method of the json-rpc
            - it must be in [get, add, set, update, delete, move, clone, exec]
        type: str
        required: false
    params:
        description:
            - the parameter collection.
        type: list
        elements: dict
        required: false
    json:
        description:
            - the raw json-formatted payload to send to fortimanager
        type: str
        required: false

"""

EXAMPLES = """
- name: Generic module
  hosts: fortimanagers
  connection: httpapi
  vars:
    adom: "root"
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Login a user
      fortinet.fortimanager.fmgr_generic:
        method: "exec"
        params:
          - url: "sys/login/user"
            data:
              - user: "APIUser"
                passwd: "Fortinet1!e"
    - name: Login another user
      fortinet.fortimanager.fmgr_generic:
        json: |
          {
           "method":"exec",
           "params":[
            {
                 "url":"sys/login/user",
                 "data":[
                    {
                       "user":"APIUser",
                       "passwd":"Fortinet1!"
                    }
                  ]
             }
            ]
          }
"""

RETURN = """
api_result:
  description: full API response, includes status code and message
  returned: always
  type: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
import json


def main():

    module_arg_spec = {
        "access_token": {"type": "str", "required": False, "no_log": True},
        "enable_log": {"type": "bool", "required": False, "default": False},
        "forticloud_access_token": {"type": "str", "required": False, "no_log": True},
        "workspace_locking_adom": {"type": "str", "required": False},
        "workspace_locking_timeout": {"type": "int", "required": False, "default": 300},
        "rc_succeeded": {"type": "list", "required": False, 'elements': 'int'},
        "rc_failed": {"type": "list", "required": False, 'elements': 'int'},
        "method": {"type": "str", "required": False},
        "params": {"type": "list", "required": False, 'elements': 'dict'},
        "json": {"type": "str", "required": False},
    }

    module = AnsibleModule(argument_spec=module_arg_spec, supports_check_mode=False)
    if not module._socket_path:
        module.fail_json(msg="Only Httpapi plugin is supported in this module.")
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('generic', None, None, None, None, module, connection)
    method = None
    params = None

    if module.params["json"]:
        raw_json_params = None
        try:
            raw_json_params = json.loads(module.params["json"])
            method = raw_json_params["method"]
            params = raw_json_params["params"]
        except Exception as e:
            module.fail_json(msg="invalid json content: %s" % (e))
    else:
        if not module.params["method"] or not module.params["params"]:
            raise AssertionError("method and params must be given!")
        method = module.params["method"]
        params = module.params["params"]

    if method not in ["get", "add", "set", "update", "delete", "move", "clone", "exec"]:
        module.fail_json(msg="method:%s not supported" % (method))

    if not isinstance(params, list):
        module.fail_json(msg="parameter:params must be an array")
    for param_block in params:
        if "url" not in param_block:
            module.fail_json(msg="url must be specified in params")
    try:
        fmgr.process_generic(method, params)

    except Exception as e:
        module.fail_json(msg="error sending request: %s" % (e))


if __name__ == "__main__":
    main()
