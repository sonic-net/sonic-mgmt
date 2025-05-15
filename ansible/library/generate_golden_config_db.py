#!/usr/bin/env python

# This ansible module is for generate golden_config_db.json
# Currently, only enable dhcp_server feature and generated related configuration in MX device
# which has dhcp_server feature.


import copy
import logging
import json
import re

from ansible.module_utils.basic import AnsibleModule
from sonic_py_common import device_info, multi_asic

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

logger = logging.getLogger(__name__)

LOSSY_HWSKU = frozenset({'Arista-7060X6-64PE-C256S2', 'Arista-7060X6-64PE-C224O8',
                         'Mellanox-SN5600-C256S1', 'Mellanox-SN5600-C224O8',
                         'Arista-7060X6-64PE-B-C512S2', 'Arista-7060X6-64PE-B-C448O16',
                         'Mellanox-SN5640-C512S2', 'Mellanox-SN5640-C448O16'})


def is_full_lossy_hwsku(hwsku):
    """
    Return True if the platform is lossy-only and PFCWD should default to ‘disable’.
    """
    return hwsku in LOSSY_HWSKU


class GenerateGoldenConfigDBModule(object):
    def __init__(self):
        self.module = AnsibleModule(argument_spec=dict(topo_name=dict(required=True, type='str'),
                                                       port_index_map=dict(require=False, type='dict', default=None),
                                                       hwsku=dict(require=False, type='str', default=None)),
                                    supports_check_mode=True)
        self.topo_name = self.module.params['topo_name']
        self.port_index_map = self.module.params['port_index_map']
        self.hwsku = self.module.params['hwsku']

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
            return {}

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

    def generate_full_lossy_golden_config_db(self):
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

        return json.dumps(golden_config_db, indent=4)

    def check_version_for_bmp(self):
        output_version = device_info.get_sonic_version_info()
        build_version = output_version['build_version']

        if re.match(r'^(\d{8})', build_version):
            version_number = int(re.findall(r'\d{8}', build_version)[0])
            if version_number > 20241130:
                return True
            else:
                return False
        elif re.match(r'^internal-(\d{8})', build_version):
            internal_version_number = int(re.findall(r'\d{8}', build_version)[0])
            if internal_version_number > 20241130:
                return True
            else:
                return False
        elif re.match(r'^master', build_version) or re.match(r'^HEAD', build_version):
            return True
        else:
            return False

    def get_config_from_minigraph(self):
        rc, out, err = self.module.run_command("sonic-cfggen -H -m -j /etc/sonic/init_cfg.json --print-data")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from minigraph: {}".format(err))
        return out

    def get_multiasic_feature_config(self, feature_key):
        rc, out, err = self.module.run_command("show runningconfiguration all")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from runningconfiguration: {}".format(err))
        running_config_db = json.loads(out)

        feature_data = {
            feature_key: {
                "auto_restart": "enabled",
                "check_up_status": "false",
                "delayed": "False",
                "has_global_scope": "False",
                "has_per_asic_scope": "True",
                "high_mem_alert": "disabled",
                "set_owner": "local",
                "state": "enabled",
                "support_syslog_rate_limit": "false"
            }
        }

        features_data = {}
        for key, value in running_config_db.items():
            if "FEATURE" in value:
                updated_feature = value["FEATURE"]
                updated_feature.update(feature_data)
                features_data[key] = {"FEATURE": updated_feature}

        return json.dumps(features_data, indent=4)

    def overwrite_feature_golden_config_db_multiasic(self, config, feature_key):
        full_config = config
        onlyFeature = config == "{}"  # FEATURE needs special handling since it does not support incremental update.
        if config == "{}":  # FEATURE needs special handling since it does not support incremental update.
            full_config = self.get_multiasic_feature_config(feature_key)

        ori_config_db = json.loads(full_config)
        if "FEATURE" not in ori_config_db:  # need dump running config FEATURE + selected feature
            feature_data = json.loads(self.get_multiasic_feature_config(feature_key))
            ori_config_db_with_feature = {}
            for key, value in ori_config_db.items():
                ori_config_db_with_feature = value.get("FEATURE", {})
                ori_config_db_with_feature.update(feature_data)
                value["FEATURE"] = ori_config_db_with_feature
                ori_config_db_with_feature[key] = value
            gold_config_db = ori_config_db_with_feature
        else:  # need existing config + selected feature
            if not onlyFeature:
                feature_data = {
                    feature_key: {
                        "auto_restart": "enabled",
                        "check_up_status": "false",
                        "delayed": "False",
                        "has_global_scope": "False",
                        "has_per_asic_scope": "True",
                        "high_mem_alert": "disabled",
                        "set_owner": "local",
                        "state": "enabled",
                        "support_syslog_rate_limit": "false"
                    }
                }
                for section, section_data in ori_config_db.items():
                    if "FEATURE" in section_data:
                        feature_section = section_data["FEATURE"]
                        feature_section.update(feature_data)
                        section_data["FEATURE"] = feature_section
            gold_config_db = ori_config_db

        return json.dumps(gold_config_db, indent=4)

    def overwrite_feature_golden_config_db_singleasic(self, config, feature_key):
        full_config = config
        onlyFeature = config == "{}"  # FEATURE needs special handling since it does not support incremental update.
        if config == "{}":
            full_config = self.get_config_from_minigraph()
        ori_config_db = json.loads(full_config)
        if "FEATURE" not in ori_config_db:
            full_config = self.get_config_from_minigraph()
            feature_config_db = json.loads(full_config)
            ori_config_db["FEATURE"] = feature_config_db.get("FEATURE", {})

        # Append the specified feature section to the original "FEATURE" section
        ori_config_db.setdefault("FEATURE", {}).setdefault(feature_key, {}).update({
            "auto_restart": "enabled",
            "check_up_status": "false",
            "delayed": "False",
            "has_global_scope": "True",
            "has_per_asic_scope": "False",
            "high_mem_alert": "disabled",
            "set_owner": "local",
            "state": "enabled",
            "support_syslog_rate_limit": "false"
        })

        # Create the gold_config_db dictionary with both "FEATURE" and the specified feature section
        if onlyFeature:
            gold_config_db = {
                "FEATURE": copy.deepcopy(ori_config_db["FEATURE"])
            }
        else:
            gold_config_db = ori_config_db

        return json.dumps(gold_config_db, indent=4)

    def generate_smartswitch_golden_config_db(self):
        rc, out, err = self.module.run_command("sonic-cfggen -H -m -j /etc/sonic/init_cfg.json --print-data")
        if rc != 0:
            self.module.fail_json(msg="Failed to get config from minigraph: {}".format(err))

        # Generate FEATURE table from init_cfg.ini
        ori_config_db = json.loads(out)
        if "DEVICE_METADATA" not in ori_config_db or "localhost" not in ori_config_db["DEVICE_METADATA"]:
            return "{}"

        ori_config_db["DEVICE_METADATA"]["localhost"]["subtype"] = "SmartSwitch"
        gold_config_db = {
            "DEVICE_METADATA": copy.deepcopy(ori_config_db["DEVICE_METADATA"])
        }

        # Generate dhcp_server related configuration
        rc, out, err = self.module.run_command("cat {}".format(TEMP_SMARTSWITCH_CONFIG_PATH))
        if rc != 0:
            self.module.fail_json(msg="Failed to get smartswitch config: {}".format(err))
        smartswitch_config_obj = json.loads(out)
        gold_config_db.update(smartswitch_config_obj)
        return json.dumps(gold_config_db, indent=4)

    def generate(self):
        module_msg = "Success to generate golden_config_db.json"
        # topo check
        if self.topo_name == "mx" or "m0" in self.topo_name:
            config = self.generate_mgfx_golden_config_db()
            module_msg = module_msg + " for mgfx"
        elif self.topo_name == "t1-28-lag":
            config = self.generate_smartswitch_golden_config_db()
            module_msg = module_msg + " for smartswitch"
        elif self.hwsku and is_full_lossy_hwsku(self.hwsku):
            module_msg = module_msg + " for full lossy hwsku"
            config = self.generate_full_lossy_golden_config_db()
        else:
            config = "{}"

        # To enable bmp feature
        if self.check_version_for_bmp() is True:
            if multi_asic.is_multi_asic():
                config = self.overwrite_feature_golden_config_db_multiasic(config, "bmp")
            else:
                config = self.overwrite_feature_golden_config_db_singleasic(config, "bmp")

        with open(GOLDEN_CONFIG_DB_PATH, "w") as temp_file:
            temp_file.write(config)
        self.module.run_command("sudo rm -f {}".format(TEMP_DHCP_SERVER_CONFIG_PATH))
        self.module.run_command("sudo rm -f {}".format(TEMP_SMARTSWITCH_CONFIG_PATH))
        self.module.exit_json(change=True, msg=module_msg)


def main():
    generate_golden_config_db = GenerateGoldenConfigDBModule()
    generate_golden_config_db.generate()


if __name__ == '__main__':
    main()
