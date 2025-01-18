#!/usr/bin/env python

# This ansible module is for generate golden_config_db.json
# Currently, only enable dhcp_server feature and generated related configuration in MX device
# which has dhcp_server feature.


import copy
import json

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
module: generate_golden_config_db.py
author: Yaqiang Zhu (yaqiangzhu@microsoft.com)
short_description:   Generate golden_config_db.json
Description:
        When load_minigraph, SONiC support to use parameter --override_config to add configuration via
        golden_config_db.json. This module is to generate required /etc/sonic/golden_config_db.json
    Input:
        topo_name: Name of current topo
'''

GOLDEN_CONFIG_DB_PATH = "/etc/sonic/golden_config_db.json"
TEMP_DHCP_SERVER_CONFIG_PATH = "/tmp/dhcp_server.json"
TEMP_SMARTSWITCH_CONFIG_PATH = "/tmp/smartswitch.json"
DUMMY_QUOTA = "dummy_single_quota"

smartswitch_hwsku_config = {
    "Cisco-8102-28FH-DPU-O-T1": {
        "dpu_num": 8,
        "port_key": "Ethernet-BP{}",
        "interface_key": "Ethernet-BP{}|18.{}.202.0/31",
        "dpu_key": "dpu{}"
    }
}


class GenerateGoldenConfigDBModule(object):
    def __init__(self):
        self.module = AnsibleModule(argument_spec=dict(topo_name=dict(required=True, type='str'),
                                                       port_index_map=dict(require=False, type='dict', default=None)),
                                    supports_check_mode=True)
        self.topo_name = self.module.params['topo_name']
        self.port_index_map = self.module.params['port_index_map']

    def generate_mgfx_golden_config_db(self):
        rc, out, err = self.module.run_command("sonic-cfggen -H -m -j /etc/sonic/init_cfg.json --print-data")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from minigraph: {}".format(err))

        # Generate config table from init_cfg.ini
        ori_config_db = json.loads(out)

        golden_config_db = {}
        if "DEVICE_METADATA" in ori_config_db:
            golden_config_db["DEVICE_METADATA"] = ori_config_db["DEVICE_METADATA"]
            if ("localhost" in golden_config_db["DEVICE_METADATA"] and
               "default_pfcwd_status" in golden_config_db["DEVICE_METADATA"]["localhost"]):
                golden_config_db["DEVICE_METADATA"]["localhost"]["default_pfcwd_status"] = "disable"

        if self.topo_name == "mx":
            golden_config_db.update(self.generate_mx_golden_config_db())
        return json.dumps(golden_config_db, indent=4)

    def generate_mx_golden_config_db(self):
        """
        If FEATURE table in init_cfg.json contains dhcp_server, enable it.
        And add dhcp_server related configuration
        """
        rc, out, err = self.module.run_command("sonic-cfggen -H -m -j /etc/sonic/init_cfg.json --print-data")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from minigraph: {}".format(err))

        # Generate FEATURE table from init_cfg.ini
        ori_config_db = json.loads(out)
        if "FEATURE" not in ori_config_db or "dhcp_server" not in ori_config_db["FEATURE"]:
            return "{}"

        ori_config_db["FEATURE"]["dhcp_server"]["state"] = "enabled"
        gold_config_db = {
            "FEATURE": copy.deepcopy(ori_config_db["FEATURE"]),
            "PORT": copy.deepcopy(ori_config_db["PORT"])
        }

        # Generate dhcp_server related configuration
        rc, out, err = self.module.run_command("cat {}".format(TEMP_DHCP_SERVER_CONFIG_PATH))
        if rc != 0:
            self.module.fail_json(msg="Failed to get dhcp_server config: {}".format(err))
        if self.port_index_map is None or self.port_index_map == {}:
            self.module.fail_json(msg="port_index_map is missing")
        dhcp_server_config_obj = json.loads(out)
        # Update DHCP_SERVER_IPV4_PORT based on port index map
        dhcp_server_port_config = {}
        for key, value in dhcp_server_config_obj["DHCP_SERVER_IPV4_PORT"].items():
            splits = key.split("|")
            new_key = "{}|{}".format(splits[0], self.port_index_map[splits[1]])
            dhcp_server_port_config[new_key] = value
        dhcp_server_config_obj["DHCP_SERVER_IPV4_PORT"] = dhcp_server_port_config

        gold_config_db.update(dhcp_server_config_obj)
        return gold_config_db

    def generate_smartswitch_golden_config_db(self):
        rc, out, err = self.module.run_command("sonic-cfggen -H -m -j /etc/sonic/init_cfg.json --print-data")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from minigraph: {}".format(err))

        # Generate FEATURE table from init_cfg.ini
        ori_config_db = json.loads(out)
        if "DEVICE_METADATA" not in ori_config_db or "localhost" not in ori_config_db["DEVICE_METADATA"]:
            return "{}"
        ori_config_db["DEVICE_METADATA"]["localhost"]["subtype"] = "SmartSwitch"
        hwsku = ori_config_db["DEVICE_METADATA"]["localhost"].get("hwsku", None)

        if "FEATURE" not in ori_config_db \
                or "dhcp_server" not in ori_config_db["FEATURE"] \
                or "dhcp_relay" not in ori_config_db["FEATURE"]:
            return "{}"
        ori_config_db["FEATURE"]["dhcp_server"]["state"] = "enabled"
        ori_config_db["FEATURE"]["dhcp_relay"]["state"] = "enabled"

        # Generate INTERFACE table for EthernetBPXX
        if "PORT" not in ori_config_db or "INTERFACE" not in ori_config_db:
            return "{}"

        if hwsku not in smartswitch_hwsku_config:
            return "{}"

        if "DPUS" not in ori_config_db:
            ori_config_db["DPUS"] = {}

        if "CHASSIS_MODULE" not in ori_config_db:
            ori_config_db["CHASSIS_MODULE"] = {}

        if "DHCP_SERVER_IPV4_PORT" not in ori_config_db:
            ori_config_db["DHCP_SERVER_IPV4_PORT"] = {}

        for i in range(smartswitch_hwsku_config[hwsku]["dpu_num"]):
            port_key = smartswitch_hwsku_config[hwsku]["port_key"].format(i)
            interface_key = smartswitch_hwsku_config[hwsku]["interface_key"].format(i, i)
            dpu_key = smartswitch_hwsku_config[hwsku]["dpu_key"].format(i)

            if port_key in ori_config_db["PORT"]:
                ori_config_db["PORT"][port_key]["admin_status"] = "up"
                ori_config_db["INTERFACE"][port_key] = {}
                ori_config_db["INTERFACE"][interface_key] = {}

            ori_config_db["CHASSIS_MODULE"]["DPU{}".format(i)] = {"admin_status": "up"}

            if dpu_key not in ori_config_db["DPUS"]:
                ori_config_db["DPUS"][dpu_key] = {}
            ori_config_db["DPUS"][dpu_key]["midplane_interface"] = dpu_key

            key = "bridge-midplane|dpu{}".format(i)
            if key not in ori_config_db["DHCP_SERVER_IPV4_PORT"]:
                ori_config_db["DHCP_SERVER_IPV4_PORT"][key] = {}
            ori_config_db["DHCP_SERVER_IPV4_PORT"][key]["ips"] = ["169.254.200.{}".format(i)]

        midplane_network_config = {
             "midplane_network": {
                 "bridge_name": "bridge-midplane",
                 "bridge_address": "169.254.200.254/24"
             }
         }
        ori_config_db["MIDPLANE_NETWORK"] = midplane_network_config
        mid_plane_bridge_config = {
                "GLOBAL": {
                    "bridge": "bridge-midplane",
                    "ip_prefix": "169.254.200.254/24"
                }
            }

        ori_config_db["MID_PLANE_BRIDGE"] = mid_plane_bridge_config

        dhcp_server_ipv4_config = {
            "DHCP_SERVER_IPV4": {
                "bridge-midplane": {
                    "gateway": "169.254.200.254",
                    "lease_time": "600000000",
                    "mode": "PORT",
                    "netmask": "255.255.255.0",
                    "state": "enabled"
                }
            }
        }
        ori_config_db["DHCP_SERVER_IPV4"] = dhcp_server_ipv4_config["DHCP_SERVER_IPV4"]
        gold_config_db = {
            "DEVICE_METADATA": copy.deepcopy(ori_config_db["DEVICE_METADATA"]),
            "FEATURE": copy.deepcopy(ori_config_db["FEATURE"]),
            "INTERFACE": copy.deepcopy(ori_config_db["INTERFACE"]),
            "PORT": copy.deepcopy(ori_config_db["PORT"]),
            "CHASSIS_MODULE": copy.deepcopy(ori_config_db["CHASSIS_MODULE"]),
            "DPUS": copy.deepcopy(ori_config_db["DPUS"]),
            "DHCP_SERVER_IPV4_PORT": copy.deepcopy(ori_config_db["DHCP_SERVER_IPV4_PORT"]),
            "MIDPLANE_NETWORK": copy.deepcopy(ori_config_db["MIDPLANE_NETWORK"]),
            "MID_PLANE_BRIDGE": copy.deepcopy(ori_config_db["MID_PLANE_BRIDGE"]),
            "DHCP_SERVER_IPV4": copy.deepcopy(ori_config_db["DHCP_SERVER_IPV4"])
        }

        # Generate dhcp_server related configuration
        rc, out, err = self.module.run_command("cat {}".format(TEMP_SMARTSWITCH_CONFIG_PATH))
        if rc != 0:
            self.module.fail_json(msg="Failed to get smartswitch config: {}".format(err))
        smartswitch_config_obj = json.loads(out)
        gold_config_db.update(smartswitch_config_obj)
        return json.dumps(gold_config_db, indent=4)

    def generate(self):
        if self.topo_name == "mx" or "m0" in self.topo_name:
            config = self.generate_mgfx_golden_config_db()
        elif self.topo_name == "t1-28-lag":
            config = self.generate_smartswitch_golden_config_db()
        else:
            config = "{}"

        with open(GOLDEN_CONFIG_DB_PATH, "w") as temp_file:
            temp_file.write(config)
        self.module.run_command("sudo rm -f {}".format(TEMP_DHCP_SERVER_CONFIG_PATH))
        self.module.run_command("sudo rm -f {}".format(TEMP_SMARTSWITCH_CONFIG_PATH))
        self.module.exit_json(change=True, msg="Success to generate golden_config_db.json")


def main():
    generate_golden_config_db = GenerateGoldenConfigDBModule()
    generate_golden_config_db.generate()


if __name__ == '__main__':
    main()
