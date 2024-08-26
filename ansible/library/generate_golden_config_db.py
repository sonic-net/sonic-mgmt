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
DUMMY_QUOTA = "dummy_single_quota"


class GenerateGoldenConfigDBModule(object):
    def __init__(self):
        self.module = AnsibleModule(argument_spec=dict(topo_name=dict(required=True, type='str'),
                                                       port_index_map=dict(require=False, type='dict', default=None)),
                                    supports_check_mode=True)
        self.topo_name = self.module.params['topo_name']
        self.port_index_map = self.module.params['port_index_map']

    def generate_mx_golden_config_db(self):
        """
        If FEATURE table in init_cfg.json contains dhcp_server, enable it.
        And add dhcp_server related configuration
        """
        rc, out, err = self.module.run_command("cat /etc/sonic/init_cfg.json")
        if rc != 0:
            self.module.fail_json(msg="Failed to get init_cfg.json: {}".format(err))

        # Generate FEATURE table from init_cfg.ini
        init_config_obj = json.loads(out)
        gold_config_db = {}
        if "FEATURE" not in init_config_obj or "dhcp_server" not in init_config_obj["FEATURE"]:
            return "{}"
        init_config_obj["FEATURE"]["dhcp_server"]["state"] = "enabled"
        gold_config_db = {"FEATURE": copy.deepcopy(init_config_obj["FEATURE"])}

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
        return json.dumps(gold_config_db, indent=4)

    def generate(self):
        if self.topo_name == "mx":
            config = self.generate_mx_golden_config_db()
        else:
            config = "{}"

        with open(GOLDEN_CONFIG_DB_PATH, "w") as temp_file:
            temp_file.write(config)
        self.module.run_command("sudo rm -f {}".format(TEMP_DHCP_SERVER_CONFIG_PATH))
        self.module.exit_json(change=True, msg="Success to generate golden_config_db.json")


def main():
    generate_golden_config_db = GenerateGoldenConfigDBModule()
    generate_golden_config_db.generate()


if __name__ == '__main__':
    main()
