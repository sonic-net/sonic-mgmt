#!/usr/bin/env python
"""Generate the port config for the fanout device."""
import logging
import os
import traceback

from ansible.module_utils.basic import AnsibleModule


logging.basicConfig(
    filename="/tmp/hwsku.log",
    level=logging.DEBUG,
)


DOCUMENTATION = """
---
module: port_config_gen
author: Longxiang Lyu (lolv@microsoft.com)
short_description: Generate the port config for the fanout device based on the hwsku and hwsku type
description:
    - Generate the port config for the fanout device
    - If the hwsku_type is predefined, parse the port config from the predefined hwsku and return
    - If the hwsku_type is dynamic, generate the hwsku based on the port breakout with script sonic_sku_create.py then return the port config
options:
    N/A
"""


class PortConfigGenerator(object):

    MACHINE_CONF = "/host/machine.conf"
    SKU_DIR_PREFIX = "/usr/share/sonic/device/"
    PORT_CONF_FILENAME = "port_config.ini"

    def __init__(self, module):
        self.module = module
        self.fanout_hwsku = module.params["hwsku"]
        self.fanout_hwsku_type = module.params["hwsku_type"].lower()
        self.fanout_connections = module.params["device_conn"]
        self.fanout_port_config = {}

    def _get_platform(self):
        with open(self.MACHINE_CONF) as machine_conf:
            for line in machine_conf:
                tokens = line.split('=')
                key = tokens[0].strip()
                value = tokens[1].strip()
                if "platform" in key:
                    return value

    @staticmethod
    def _read_from_port_config(filepath):
        port_config = {}
        with open(filepath) as fd:
            lines = fd.readlines()
            header = lines[0].strip("#\n ")
            keys = header.split()
            alias_index = keys.index("alias")
            for line in lines[1:]:
                if not line:
                    continue
                values = line.split()
                # port alias as the key
                port_config[values[alias_index]] = dict(zip(keys, values))
        return port_config

    def init_platform(self):
        self.fanout_platform = self._get_platform()
        PortConfigGenerator.SKU_DIR_PREFIX = os.path.join(PortConfigGenerator.SKU_DIR_PREFIX, self.fanout_platform)
        with open(os.path.join(self.SKU_DIR_PREFIX, "default_sku")) as fd:
            self.platform_default_hwsku = fd.read().strip()
        self.platform_supported_hwsku_list = [_ for _ in os.listdir(self.SKU_DIR_PREFIX) if os.path.isdir(os.path.join(self.SKU_DIR_PREFIX, _))]

    def init_port_config(self):
        """Init the port config to be used by fanout."""
        if self.fanout_hwsku_type == "predefined":
            if self.fanout_hwsku not in self.platform_supported_hwsku_list:
                raise ValueError("Unsupported hwsku %s, supported: %s" % (self.fanout_hwsku, self.platform_supported_hwsku_list))
            hwsku_port_config = self._read_from_port_config(os.path.join(self.SKU_DIR_PREFIX, self.fanout_hwsku, self.PORT_CONF_FILENAME))

            self.fanout_port_config = self.fanout_connections.copy()
            for port_alias, port_config in self.fanout_port_config.items():
                if port_alias not in hwsku_port_config:
                    raise ValueError("Port %s is not defined in hwsku %s port config" % (port_alias, self.fanout_hwsku))
                port_config.update(hwsku_port_config[port_alias])

            # add port configs for those ports that have no connections in the connection graph file
            for port_alias, port_config in hwsku_port_config.items():
                if port_alias not in self.fanout_port_config:
                    self.fanout_port_config[port_alias] = port_config

        else:
            # TODO: create hwsku if hwsku_type is dynamic
            # 1. parse the default port config file
            # 2. fill missing ports in device_conn and create the device port xml file
            # 3. create the xml file with sonic_sku_create.py
            pass


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hwsku=dict(required=True, type=str),
            hwsku_type=dict(default="predefined", type=str),
            device_conn=dict(required=True, type=dict)
        )
    )

    gen = PortConfigGenerator(module)
    try:
        gen.init_platform()
        gen.init_port_config()
    except Exception as detail:
        module.fail_json(msg="ERROR: %s, TRACEBACK: %s" % (repr(detail), traceback.format_exc()))
    module.exit_json(
        ansible_facts=dict(
            fanout_platform=gen.fanout_platform,
            fanout_hwsku=gen.fanout_hwsku,
            fanout_port_config=gen.fanout_port_config
        )
    )


if __name__ == '__main__':
    main()
