#!/usr/bin/env python3
import yaml
import argparse
import json
import sys

TOPO_PLATFORM_FILE_MAP = 'topo_and_platform_to_filename_map.json'
DEFAULT_SONIC_IMAGE_PATH = '../../sonic-cisco-8000.bin'

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
parser.add_argument("--onie-install", help = "path to use for onie install image", nargs='?', const='', default = '', required=False)
parser.add_argument("--npl-path", help = "npl path", nargs='?', const='', default = '', required=False)
parser.add_argument("--npl-suite-ver", help = "npl suite version", nargs='?', const='', default = '', required=False)
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

with open(topology_file, "r") as fd:
    topo = yaml.safe_load(fd)

    for device in topo["devices"]:
        if "onie-install" not in topo["devices"][device]:
            continue
            
        print(f"Modifying settings for device {device}...")
        #specify onie install image, use default if not set
        if args.onie_install:
            print(f"set onie-install to: '{args.onie_install}'")
            topo["devices"][device]["onie-install"] = args.onie_install
        else:
            print(f"onie-install path not specified. Setting to default path: '{DEFAULT_SONIC_IMAGE_PATH}'")
            topo["devices"][device]["onie-install"] = DEFAULT_SONIC_IMAGE_PATH

        #populate npl suite version and path. Not going to populate by default
        if args.npl_path and args.npl_suite_ver:
            if "vxr_sim_config" not in topo["devices"][device]:
                topo["devices"][device]["vxr_sim_config" ] = {}
                topo["devices"][device]["vxr_sim_config" ]["shelf"] = {}

            print(f"setting ConfigS1NpsuiteVer to '{args.npl_suite_ver}'")
            print(f"setting ConfigS1NplPath to '{args.npl_path}'")
            topo["devices"][device]["vxr_sim_config"]["shelf"]["ConfigS1NpsuiteVer"] = args.npl_suite_ver
            topo["devices"][device]["vxr_sim_config"]["shelf"]["ConfigS1NplPath"] = args.npl_path
        
        #populate dut password, default cisco/cisco123
        print(f"set DUT username/pass to '{args.dut_username}/{args.dut_password}'")
        topo["devices"][device]["linux_username"] = args.dut_username
        topo["devices"][device]["linux_password"] = args.dut_password
        print(f"Modify settings for device {device} done.")

with open(topology_file, "w") as fd:
    yaml.safe_dump(topo, fd)
