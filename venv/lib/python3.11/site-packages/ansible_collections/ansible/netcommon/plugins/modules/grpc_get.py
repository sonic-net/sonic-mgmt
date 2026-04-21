#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
module: grpc_get
version_added: "3.1.0"
author:
    - "Ganesh Nalawade (@ganeshrn)"
    - "Gomathi Selvi S (@GomathiselviS)"
short_description: Fetch configuration/state data from gRPC enabled target hosts.
description:
    - gRPC is a high performance, open-source universal RPC framework.
    - This module allows the user to fetch configuration and state data from gRPC
      enabled devices.
options:
  section:
    description:
      - This option specifies the string which acts as a filter to restrict the portions of
        the data to be retrieved from the target host device. If this option is not specified the entire
        configuration or state data is returned in response provided it is supported by target host.
    aliases:
    - filter
    type: str
  command:
    description:
      - The option specifies the command to be executed on the target host and return the response
        in result. This option is supported if the gRPC target host supports executing CLI command
        over the gRPC connection.
    type: str
  display:
    description:
      - Encoding scheme to use when serializing output from the device. The encoding scheme
        value depends on the capability of the gRPC server running on the target host.
        The values can be I(json), I(text) etc.
    type: str
  data_type:
    description:
      - The type of data that should be fetched from the target host. The value depends on the
        capability of the gRPC server running on target host. The values can be I(config), I(oper)
        etc. based on what is supported by the gRPC server. By default it will return both configuration
        and operational state data in response.
    type: str
requirements:
  - grpcio
  - protobuf
notes:
  - This module requires the gRPC system service be enabled on
    the target host being managed.
  - This module supports the use of connection=ansible.netcommon.grpc.
  - This module requires the value of 'ansible_network_os or grpc_type' configuration option (refer ansible.netcommon.grpc
    connection plugin documentation) be defined as an inventory variable.
  - Tested against iosxrv 9k version 6.1.2.
"""

EXAMPLES = """
- name: Get bgp configuration data
  grpc_get:
    section:
      Cisco-IOS-XR-ip-static-cfg:router-static:
        - null
- name: run cli command
  grpc_get:
    command: "show version"
    display: text
"""

RETURN = """
stdout:
  description: The raw string containing configuration or state data
               received from the gRPC server.
  returned: always apart from low-level errors (such as action plugin)
  type: str
  sample: '...'
stdout_lines:
  description: The value of stdout split into a list
  returned: always apart from low-level errors (such as action plugin)
  type: list
  sample: ['...', '...']
output:
  description: A dictionary representing a JSON-formatted response, if the response
               is a valid json string
  returned: when the device response is valid JSON
  type: list
  sample: |
        [{
            "Cisco-IOS-XR-ip-static-cfg:router-static": {
                "default-vrf": {
                    "address-family": {
                        "vrfipv4": {
                            "vrf-unicast": {
                                "vrf-prefixes": {
                                    "vrf-prefix": [
                                        {
                                            "prefix": "0.0.0.0",
                                            "prefix-length": 0,
                                            "vrf-route": {
                                                "vrf-next-hop-table": {
                                                    "vrf-next-hop-interface-name-next-hop-address": [
                                                        {
                                                            "interface-name": "MgmtEth0/RP0/CPU0/0",
                                                            "next-hop-address": "10.0.2.2"
                                                        }
                                                    ]
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        }]
"""
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.connection import ConnectionError

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_list
from ansible_collections.ansible.netcommon.plugins.module_utils.network.grpc.grpc import (
    get,
    get_capabilities,
    run_cli,
)


try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def main():
    """entry point for module execution"""
    argument_spec = dict(
        section=dict(type="str", aliases=["filter"]),
        command=dict(type="str"),
        display=dict(type="str"),
        data_type=dict(type="str"),
    )

    mutually_exclusive = [["section", "command"]]
    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=mutually_exclusive,
        supports_check_mode=True,
    )
    capabilities = get_capabilities(module)

    operations = capabilities["server_capabilities"]

    if module.params["section"]:
        section = json.dumps(yaml.safe_load(module.params["section"]))
    else:
        section = None
    command = module.params["command"]
    display = module.params["display"]
    data_type = module.params["data_type"]

    supported_display = operations.get("display", [])
    if display and display not in supported_display:
        module.fail_json(
            msg="display option '%s' is not supported on this target host. Valid value is one of '%s'"
            % (display, supported_display.join(", "))
        )

    if command and not operations.get("supports_cli_command", False):
        module.fail_json(msg="command option '%s' is not supported on this target host" % command)

    supported_data_type = operations.get("data_type", [])
    if data_type and data_type not in supported_data_type:
        module.fail_json(
            msg="data_type option '%s' is not supported on this target host. Valid value is one of %s"
            % (data_type, supported_data_type.join(","))
        )

    result = {"changed": False}
    output = []
    try:
        if command:
            response, err = run_cli(module, command, display)
        else:
            response, err = get(module, section, data_type)
        try:
            output = json.loads(response)
        except ValueError:
            module.warn(to_text(err, errors="surrogate_then_replace"))

    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc, errors="surrogate_then_replace"), code=exc.code)
    result["stdout"] = response

    if output:
        result["output"] = to_list(output)
    else:
        result["output"] = to_list(response)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
