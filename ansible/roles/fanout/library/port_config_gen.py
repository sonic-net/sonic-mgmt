#!/usr/bin/env python
"""Generate the port config for the fanout device."""
import os
import re
import tempfile
import traceback
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET

from collections import OrderedDict
from natsort import natsorted
from ansible.module_utils.basic import AnsibleModule


DOCUMENTATION = """
---
module: port_config_gen
author: Longxiang Lyu (lolv@microsoft.com)
short_description: Generate the port config for the fanout device based on the hwsku and hwsku type
description:
    - Generate the port config for the fanout device
    - If the hwsku_type is predefined, parse from the predefined hwsku and return the port config
    - If the hwsku_type is dynamic, generate the hwsku based on the port breakout with script sonic_sku_create.py then return the port config
options:
    N/A
"""


class PortConfigGenerator(object):

    MACHINE_CONF = "/host/machine.conf"
    SONIC_VERSION_FILE = "/etc/sonic/sonic_version.yml"
    HWSKU_DIR_PREFIX = "/usr/share/sonic/device/"
    PORT_CONF_FILENAME = "port_config.ini"
    PORT_ALIAS_PATTERNS = (
        re.compile(r"^etp(?P<port_index>\d+)(?P<lane>[a-d]?)"),
        re.compile(r"^Ethernet(?P<port_index>\d+)(/)?(?(2)(?P<lane>[1-4]+))")
    )

    def __init__(self, module):
        self.module = module
        self.fanout_hwsku = module.params["hwsku"]
        self.fanout_hwsku_type = module.params["hwsku_type"].lower()
        self.fanout_connections = module.params["device_conn"]
        self.fanout_port_config = {}

    def _get_asic_type(self):
        with open(self.SONIC_VERSION_FILE) as version_f:
            for line in version_f:
                if "asic_type" in line:
                    return line.split(":")[1].strip()
        raise ValueError("Failed to retrieve asic type from '%s'" % self.SONIC_VERSION_FILE)

    def _get_platform(self):
        with open(self.MACHINE_CONF) as machine_conf:
            for line in machine_conf:
                if not line:
                    continue
                if "platform" in line:
                    return line.split("=")[1].strip()
        raise ValueError("Failed to retrieve platform from '%s'" % self.MACHINE_CONF)

    def _get_platform_default_hwsku(self):
        with open(os.path.join(self.HWSKU_DIR_PREFIX, "default_sku")) as fd:
            return fd.read().strip().split()[0]

    def _parse_interface_alias(self, port_alias):
        for alias_pattern in self.PORT_ALIAS_PATTERNS:
            m = alias_pattern.match(port_alias)
            if m:
                return m.group("port_index"), m.group("lane")
        raise ValueError("Invalid parse port alias format %s" % port_alias)

    def _create_sonic_sku(self, port_xml_file):
        cmd = "sonic_sku_create.py -f %s -k %s" % (port_xml_file, self.fanout_hwsku)
        ret_code, stdout, stderr = self.module.run_command(cmd, executable='/bin/bash', use_unsafe_shell=True)
        if ret_code:
            raise RuntimeError("Failed to create new hwsku:\nstdout: %s\nstderr: %s\n" % (stdout, stderr))

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

    @staticmethod
    def _prettify(xml_elem):
        """Output a xml element with indentation."""
        xml_output = ET.tostring(xml_elem, encoding="utf-8")
        reparsed_output = minidom.parseString(xml_output)
        return reparsed_output.toprettyxml(indent="  ")

    def init_platform(self):
        self.fanout_asic_type = self._get_asic_type()
        self.fanout_platform = self._get_platform()
        PortConfigGenerator.HWSKU_DIR_PREFIX = os.path.join(PortConfigGenerator.HWSKU_DIR_PREFIX, self.fanout_platform)
        self.platform_default_hwsku = self._get_platform_default_hwsku()
        self.platform_supported_hwsku_list = [_ for _ in os.listdir(self.HWSKU_DIR_PREFIX) if os.path.isdir(os.path.join(self.HWSKU_DIR_PREFIX, _))]

    def init_port_config(self):
        """Init the port config to be used by fanout."""
        if self.fanout_hwsku_type == "predefined":
            if self.fanout_hwsku not in self.platform_supported_hwsku_list:
                raise ValueError("Unsupported hwsku %s, supported: %s" % (self.fanout_hwsku, self.platform_supported_hwsku_list))

        elif self.fanout_hwsku_type == "dynamic":
            # fill missing ports in device_conn from the default port config file
            default_hwsku_port_config = self._read_from_port_config(os.path.join(self.HWSKU_DIR_PREFIX, self.platform_default_hwsku, self.PORT_CONF_FILENAME))
            default_hwsku_port_index_to_port_config = {
                self._parse_interface_alias(port_alias)[0]: port_config for port_alias, port_config in default_hwsku_port_config.items()
            }

            fanout_connection = self.fanout_connections.copy()
            for port_alias, port_config in fanout_connection.items():
                port_index = self._parse_interface_alias(port_alias)[0]
                default_hwsku_port_index_to_port_config.pop(port_index, None)
    
            for port_config in default_hwsku_port_index_to_port_config.values():
                fanout_connection[port_config['alias']] = port_config

            # create the xml file as input to sonic_sku_create.py script
            self.fanout_hwsku = self.platform_default_hwsku + "_NEW"
            xml_file_root = ET.Element("DeviceInfo", attrib=OrderedDict(Vendor="Microsoft", HwSku=self.fanout_hwsku))
            ether_elem = ET.SubElement(xml_file_root, "Ethernet")
            
            for index, port_alias in enumerate(natsorted(fanout_connection.keys()), start=1):
                ET.SubElement(ether_elem, "Interface", attrib=OrderedDict(Index=str(index), PortName=str(index), InterfaceName=port_alias, Speed=fanout_connection[port_alias].get("speed", "100000")))

            with tempfile.NamedTemporaryFile(delete=False) as xml_file:
                xml_file.write(self._prettify(xml_file_root))
                xml_file.flush()
                self._create_sonic_sku(xml_file.name)

        hwsku_port_config = self._read_from_port_config(os.path.join(self.HWSKU_DIR_PREFIX, self.fanout_hwsku, self.PORT_CONF_FILENAME))

        self.fanout_port_config = self.fanout_connections.copy()
        for port_alias, port_config in self.fanout_port_config.items():
            if port_alias not in hwsku_port_config:
                raise ValueError("Port %s is not defined in hwsku %s port config" % (port_alias, self.fanout_hwsku))
            port_config.update(hwsku_port_config[port_alias])

        # add port configs for those ports that have no connections in the connection graph file
        for port_alias, port_config in hwsku_port_config.items():
            if port_alias not in self.fanout_port_config:
                self.fanout_port_config[port_alias] = port_config


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
