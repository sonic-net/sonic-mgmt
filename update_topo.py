#!/usr/bin/env python3
import yaml
import argparse
import json
import sys
import os

SIM_CFG_FILE = "../sim-cfg.yml"
TOPO_PLATFORM_FILE_MAP = 'topo_and_platform_to_filename_map.json'

platform_set = set()

with open('infra/'+TOPO_PLATFORM_FILE_MAP) as cfg_file:
    TOPO_PLATFORM_FILE_DICT = json.load(cfg_file)

for topology in TOPO_PLATFORM_FILE_DICT:
    platform_set.update(TOPO_PLATFORM_FILE_DICT[topology].keys())

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--topology", help = "name of the topology ", nargs='?', const='', default = '', required=False, choices=TOPO_PLATFORM_FILE_DICT.keys())
parser.add_argument("-p", "--platform", help = "type of the dut platform ", nargs='?', const='', default = '', required=False, choices=platform_set)
parser.add_argument('-f', '--topo_yaml', type=str, help='topo yaml file', required=False,default=None)
parser.add_argument("--dut-username", help = "username for the dut ", nargs='?', const='', default = 'cisco', required=False)
parser.add_argument("--dut-password", help = "password for the dut ", nargs='?', const='', default = 'cisco123', required=False)
args = parser.parse_args()

topology_file = args.topo_yaml
topology = args.topology
platform = args.platform

#get topo_yaml from topo_type
if not topology_file:
    if not topology:
        print(f"ERROR: Topology not specified. If topology file is not provided, need topology and platform specified so we can find the yaml file via map file {TOPO_PLATFORM_FILE_MAP}")
    elif not platform:
        print(f"ERROR: Platform not specified. If topology file is not provided, need topology and platform specified so we can find the yaml file via map file {TOPO_PLATFORM_FILE_MAP}")
    elif topology in TOPO_PLATFORM_FILE_DICT and platform in TOPO_PLATFORM_FILE_DICT[topology]:
            topology_file = TOPO_PLATFORM_FILE_DICT[topology][platform]["pyvxr_yaml_file"][1:]
    else:
        print(f"ERROR: Topology and platform pair specified does not exist in topo map file {TOPO_PLATFORM_FILE_MAP}")

if not topology_file:
    sys.exit(1)

with open(SIM_CFG_FILE, "r") as fd:
    sim_cfg = yaml.safe_load(fd)

with open(topology_file, "r") as fd:
    topo = yaml.safe_load(fd)

    for device in topo["devices"]:
        if "onie-install" not in topo["devices"][device]:
            continue

        if os.getenv("SANITY_TYPE") == 'sonic-mgmt':
            npl_path = sim_cfg["npl_path"].replace("mb", "vxr")
        else: 
            npl_path = sim_cfg["npl_path"]

        topo["devices"][device]["onie-install"] = "../../sonic-cisco-8000.bin"
        if "vxr_sim_config" not in topo["devices"][device]:
            topo["devices"][device]["vxr_sim_config" ] = {}
        topo["devices"][device]["vxr_sim_config"]["shelf"] = {
            "ConfigS1NpsuiteVer": sim_cfg["npsuite"],
            "ConfigS1NplPath": sim_cfg["npl_path"].replace("mb", "vxr")
            }
        topo["devices"][device]["linux_username"] = args.dut_username
        topo["devices"][device]["linux_password"] = args.dut_password

with open(topology_file, "w") as fd:
    yaml.safe_dump(topo, fd)
