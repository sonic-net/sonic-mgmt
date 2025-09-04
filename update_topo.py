#!/usr/bin/env python3
import yaml
import argparse
import json
import sys
import os
import time
import re

TOPO_PLATFORM_FILE_MAP = 'topo_and_platform_to_filename_map.json'
DEFAULT_SONIC_IMAGE_PATH = '../../sonic-cisco-8000.bin'
DOCKER_PTF_QCOW_IMAGE_PATH_TEMPLATE = '/auto/vxr1/sonic/cicd/docker_ptf_qcow_images/ptf_docker_{SONIC_TEST_VERSION}.qcow2'

platform_set = set()

with open('infra/'+TOPO_PLATFORM_FILE_MAP) as cfg_file:
    TOPO_PLATFORM_FILE_DICT = json.load(cfg_file)

for topology in TOPO_PLATFORM_FILE_DICT:
    platform_set.update(TOPO_PLATFORM_FILE_DICT[topology].keys())

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--topology", help = "name of the topology ", nargs='?', const='', default = '', required=False, choices=TOPO_PLATFORM_FILE_DICT.keys())
parser.add_argument("-p", "--platform", help = "type of the dut platform ", nargs='?', const='', default = '', required=False, choices=platform_set)
parser.add_argument('-f', '--topo_yaml', type=str, help='topo yaml file', required=False,default=None)
parser.add_argument('-g', '--goldencode', type=str, help='goldencode url', required=False,default=None)
parser.add_argument("--dut-username", help = "username for the dut ", nargs='?', const='', default = 'admin', required=False)
parser.add_argument("--dut-password", help = "password for the dut ", nargs='?', const='', default = 'password', required=False)
parser.add_argument("--onie-install", help = "path to use for onie install image", nargs='?', const='', default = '', required=False)
parser.add_argument("--npl-path", help = "npl path", nargs='?', const='', default = '', required=False)
parser.add_argument("--npl-suite-ver", help = "npl suite version", nargs='?', const='', default = '', required=False)
parser.add_argument('--disable-ztp', action='store_true', help='add command to disable ztp', default=False)
args = parser.parse_args()

topology_file = args.topo_yaml
topology = args.topology
platform = args.platform
disable_ztp = args.disable_ztp

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

def extract_branch_from_goldencode_url(goldencode_url):
    """
    Extract sonic-test branch from a GOLDENCODE URL.
    Returns None if no match found.
    """
    filename = goldencode_url.split("/")[-1]

    # Look for 6 digits starting with 20 (i.e., 20YYMM)
    if 'master' in filename:
        return 'master'
    else:
        match = re.search(r'20\d{4}', filename)
        if match:
            return match.group(0)

    print(f"ERROR! Could not find sonic-test branch from goldencode url: {goldencode_url}")
    return None

print(f"using topology file: '{topology_file}'")

with open(topology_file, "r") as fd:
    topo = yaml.safe_load(fd)
    build_id = os.getenv('BUILD_ID') or f"non_cicd_sanity_{str(time.time())}"
    job_base_name = os.getenv('JOB_BASE_NAME') or ""
    sonic_cicd_id = f"{job_base_name}_{build_id}"
    goldencode = args.goldencode
    image_url = os.getenv('IMAGE_NAME') or ""
    
    sonic_test_branch = "unknown"
    sonic_test_version = None

    if goldencode:
        sonic_test_branch = goldencode.split('golden_code_')[1].split('.tar')[0]
        #extract upstream sonic test branch from goldencode, e.g. golden_code_202405.tar.gz --> 202405. None if not found
        sonic_test_version = extract_branch_from_goldencode_url(goldencode)

    topo["simulation"]["telemetry"] = {
        "sonic_cicd_id": sonic_cicd_id,
        "test_branch": sonic_test_branch,
        "goldencode": goldencode,
        "image_name": image_url,
        "testsuite_id": f"{topology}_{platform}_sim"
    }

    print(f"added telemetry info in simulation.telemetry: \n{json.dumps(topo['simulation']['telemetry'], indent=2)}")


    for device in topo["devices"]:
        # handle docker_ptf related modifications
        if device == "docker_ptf":
            if not sonic_test_version:
                print("could not determine sonic-test version from golencode! Will not modify the docker ptf version")
            else:
                docker_ptf_image = DOCKER_PTF_QCOW_IMAGE_PATH_TEMPLATE.format(SONIC_TEST_VERSION=sonic_test_version)
                if not os.path.isfile(docker_ptf_image):
                    print(f"WARNING: docker_ptf_image file '{docker_ptf_image}' does not exist! Will not modify the docker ptf version")
                    continue
                print(f"Set docker ptf image to: {docker_ptf_image}")
                topo["devices"][device]["image"] = docker_ptf_image
            continue

        # handle DUT related modifications
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

        #if disable_ztp:
        if disable_ztp:
            topo["devices"][device]["pre_cli"] = topo["devices"][device].get("pre_cli", '').rstrip('\n') + '\nsudo ztp disable -y\n'
            print("ZTP disabled")

        #populate dut password, default cisco/cisco123
        print(f"set DUT username/pass to '{args.dut_username}/{args.dut_password}'")
        topo["devices"][device]["linux_username"] = args.dut_username
        topo["devices"][device]["linux_password"] = args.dut_password
        print(f"Modify settings for device {device} done.")

with open(topology_file, "w") as fd:
    yaml.safe_dump(topo, fd)
