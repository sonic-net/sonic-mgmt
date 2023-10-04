#!/usr/bin/env python3
import yaml
import argparse
import json

SIM_CFG_FILE = "../sim-cfg.yml"

platform_set = set()

with open('infra/topo_and_platform_to_filename_map.json') as cfg_file:
    TOPO_AND_DEVICE_TYPE_TO_TOPO_FILE_MAP = json.load(cfg_file)

for topology in TOPO_AND_DEVICE_TYPE_TO_TOPO_FILE_MAP:
    platform_set.update(TOPO_AND_DEVICE_TYPE_TO_TOPO_FILE_MAP[topology].keys())

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--topology", help = "name of the topology ", nargs='?', const='', default = '', required=True, choices=TOPO_AND_DEVICE_TYPE_TO_TOPO_FILE_MAP.keys())
parser.add_argument("-p", "--platform", help = "type of the dut platform ", nargs='?', const='', default = '', required=True, choices=platform_set)
args = parser.parse_args()

topology_file = TOPO_AND_DEVICE_TYPE_TO_TOPO_FILE_MAP[args.topology][args.platform][1:]

with open(SIM_CFG_FILE, "r") as fd:
    sim_cfg = yaml.safe_load(fd)

with open(topology_file, "r") as fd:
    topo = yaml.safe_load(fd)

    topo["devices"]["sonic_dut"]["onie-install"] = "../../sonic-cisco-8000.bin"
    topo["devices"]["sonic_dut"]["vxr_sim_config"] = {
        "shelf": {
            "ConfigS1NpsuiteVer": sim_cfg["npsuite"],
            "ConfigS1NplPath": sim_cfg["npl_path"]
        }
    }

with open(topology_file, "w") as fd:
    yaml.safe_dump(topo, fd)
