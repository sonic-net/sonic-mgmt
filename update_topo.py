#!/usr/bin/env python3
import yaml
import argparse

TOPOLOGY_FILES = {
     "T1_churchill": "pyvxr_yaml_files/churchill_sonic_t1_topo.yaml",
     "T0_churchill": "pyvxr_yaml_files/churchill_sonic_t0_topo.yaml",
     "T0": "pyvxr_yaml_files/mth64_sonic_t0-64_topo.yaml",
     "T1": "pyvxr_yaml_files/mth64_sonic_t1_64_lag_topo.yaml"
}
SIM_CFG_FILE = "../sim-cfg.yml"

parser = argparse.ArgumentParser()
parser.add_argument("topology", choices=TOPOLOGY_FILES.keys())
args = parser.parse_args()
topology_file = TOPOLOGY_FILES[args.topology]

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
