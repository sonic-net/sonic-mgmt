#!/usr/bin/env python3
import sys
import yaml

T0_TOPOLOGY_FILE = "pyvxr_yaml_files/mth64_sonic_t0-64_topo.yaml"
T1_TOPOLOGY_FILE = "pyvxr_yaml_files/mth64_sonic_t1_64_lag_topo.yaml"
SIM_CFG_FILE = "../sim-cfg.yml"


if __name__=="__main__":
    if len(sys.argv) != 2:
        print("ERROR: invalid arguement numbers!")
        exit(1)
    else:
        sim_cfg_f = open(SIM_CFG_FILE, "r")
        sim_cfg = yaml.safe_load(sim_cfg_f)
        sim_cfg_f.close()
        if sys.argv[1] == "T0":
            topo_f = open(T0_TOPOLOGY_FILE, "r")
            topo = yaml.safe_load(topo_f)
            topo_f.close()


            topo["devices"]["sonic_dut"]["onie-install"] = "../../sonic-cisco-8000.bin"
            topo["devices"]["sonic_dut"]["vxr_sim_config"]["shelf"]["ConfigS1NpsuiteVer"] = sim_cfg["npsuite"]
            topo["devices"]["sonic_dut"]["vxr_sim_config"]["shelf"]["ConfigS1NplPath"] = sim_cfg["npl_path"]

            topo_f = open(T0_TOPOLOGY_FILE, "w")
            yaml.safe_dump(topo, topo_f)
            topo_f.close()
        elif sys.argv[1] == "T1":
            topo_f = open(T1_TOPOLOGY_FILE, "r")
            topo = yaml.safe_load(topo_f)
            topo_f.close()

            topo["devices"]["sonic_dut"]["onie-install"] = "../../sonic-cisco-8000.bin"
            topo["devices"]["sonic_dut"]["vxr_sim_config"]["shelf"]["ConfigS1NpsuiteVer"] = sim_cfg["npsuite"]
            topo["devices"]["sonic_dut"]["vxr_sim_config"]["shelf"]["ConfigS1NplPath"] = sim_cfg["npl_path"]

            topo_f = open(T1_TOPOLOGY_FILE, "w")
            yaml.safe_dump(topo, topo_f)
            topo_f.close()
        else:
            print("ERROR: invalid arguement: %s" %sys.argv) 
            exit(1)
