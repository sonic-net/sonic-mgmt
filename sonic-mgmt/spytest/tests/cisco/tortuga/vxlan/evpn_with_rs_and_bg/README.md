# EVPN Test Suite

This directory contains test cases and supporting files for validating EVPN (Ethernet VPN).

## Structure

- `test_*.py`: Automated test scripts for various EVPN scenarios.
- `data/`: Sample configuration files and test data.
- `README.md`: This documentation.

## Purpose

The tests in this directory are designed to:

- Verify EVPN control and data plane operations.
- Validate interoperability and protocol compliance.
- Ensure correct forwarding and MAC/IP learning.

## Requirements

- Python 3.x
- Pytest
- requests


## Bring up SIM

Bring up SIM and gather port information (cmono)

```
vxr start <sonic-test_path>/pyvxr_yaml_files/evpn_D9.yaml

vxr vxr.py ports
```

### Setup IXIA

Connect to sonic-mgmt vm, setup the IXIA VM:
```
wget http://10.29.158.43/builds/keysight-u18070-10-0.tar
docker load -i keysight-u18070.tar

git clone https://wwwin-github.cisco.com/whitebox/sonic-test.git
cd sonic-test
git checkout <your branch>
```

### Topology file updates

Update the IP addresses of the nodes (follow the mapping described in the earlier sections). The topology (cmono) file is located here:
```
cd sonic-test/sonic-mgmt/spytest
cp sonic-test/sonic-mgmt/spytest/tests/cisco/ip_fabric/evpn/topology/evpn_rs_bg_topo.yaml .

Update evpn_rs_bg_topo.yaml
```

Update the IXIA IP addresses under the TGEN device type:
```
"T1_chassis": {
    "HostAgent": "172.26.228.188",
    "SimLocalIp": "172.26.228.188",
    "mgmt_ip": "192.168.122.28", ====> ip
    "monitor0": 10097,
    "plugin": "x86_64",
    "redir443": 28933,
    "serial0": 17165
},
"T1_gui": {
    "HostAgent": "172.26.228.188",
    "SimLocalIp": "172.26.228.188",
    "mgmt_ip": "192.168.122.163", ====> ix_server
    "monitor0": 25815,
    "plugin": "x86_64",
    "redir443": 27701,
    "serial0": 12523
},
```

### Run tests

```
cd sonic-test/sonic-mgmt/spytest
 
docker run -v $PWD:/data --name 'ixia_sonic_mgmt' -itd spytest/keysight-u18:9.20.2201.70 /bin/bash

docker exec -it ixia_sonic_mgmt bash
cd /data
pip install monotonic
unset https_proxy http_proxy

./bin/spytest --testbed /data/evpn_rs_bg_topo.yaml --device-feature-group master --module-init-max-timeout=7200 --tc-max-timeout=7200 --skip-init-checks --include-parameterized-test --skip-init-config --topology-check=skip /data/tests/cisco/tortuga/vxlan/evpn/test_control_plane.py --ixia-config-file=<> --ixia-api-key=<> --ixia-traffic-profile=<l2/l3>
```