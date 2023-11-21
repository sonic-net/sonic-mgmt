#!/usr/bin/env python3
import yaml
import argparse
import json

SIM_CFG_FILE = "../sim-cfg.yml"
TOPO_PLATFORM_FILE_MAP = 'topo_and_platform_to_filename_map.json'

platform_set = set()

with open('infra/'+TOPO_PLATFORM_FILE_MAP) as cfg_file:
    TOPO_PLATFORM_FILE_DICT = json.load(cfg_file)

for topology in TOPO_PLATFORM_FILE_DICT:
    platform_set.update(TOPO_PLATFORM_FILE_DICT[topology].keys())

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--topology", help = "name of the topology ", nargs='?', const='', default = '', required=True, choices=TOPO_PLATFORM_FILE_DICT.keys())
parser.add_argument("-p", "--platform", help = "type of the dut platform ", nargs='?', const='', default = '', required=True, choices=platform_set)
parser.add_argument("--dut-username", help = "username for the dut ", nargs='?', const='', default = 'cisco', required=False)
parser.add_argument("--dut-password", help = "password for the dut ", nargs='?', const='', default = 'cisco123', required=False)
args = parser.parse_args()

topology_file = TOPO_PLATFORM_FILE_DICT[args.topology][args.platform][1:]

with open(SIM_CFG_FILE, "r") as fd:
    sim_cfg = yaml.safe_load(fd)

with open(topology_file, "r") as fd:
    topo = yaml.safe_load(fd)

    topo["devices"]["sonic_dut"]["onie-install"] = "../../sonic-cisco-8000.bin"
    if "vxr_sim_config" not in topo["devices"]["sonic_dut"]:
        topo["devices"]["sonic_dut"]["vxr_sim_config" ] = {}
    topo["devices"]["sonic_dut"]["vxr_sim_config"]["shelf"] = {
        "ConfigS1NpsuiteVer": sim_cfg["npsuite"],
        "ConfigS1NplPath": sim_cfg["npl_path"]
        }
    topo["devices"]["sonic_dut"]["linux_username"] = args.dut_username
    topo["devices"]["sonic_dut"]["linux_password"] = args.dut_password

with open(topology_file, "w") as fd:
    yaml.safe_dump(topo, fd)
