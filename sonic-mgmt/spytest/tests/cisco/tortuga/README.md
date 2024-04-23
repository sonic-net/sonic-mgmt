# Tortuga based Spytest Scripts

This directory hosts the test cases written to support VXLAN features on SONiC. Tortuga is one of the first customers to use VXLAN features so these test cases are written with that in mind.

However, these test cases do not depend on any Tortuga related software. So, they are testing pure SONiC VXLAN features.

## Understanding Topology

There are two important files that needs our attention:

a. SIM Config File<br>
b. Topology File<br>

The SIM config file brings up the connections among different nodes in the system among other things. This is applicable only to VXR based runs.

The Topology file carries the same information but the data is consumed by the tests.

So it is important to keep the SIM config file and the Topology file consistent with each other. Consistency means the connections between nodes as described in the SIM config file and the Topology file MUST match.

For example, these files are consistent:

SIM Config File : ```pyvxr_yaml_files/tortuga_spytest_5D_linux_ixia_mathilda.yaml```<br>
Topology File   : ```spytest_tb_files/tortuga_spytest_topo_4D_ixia_mathilda.yaml```

These tests use 2 Leaf - 2 Spine topology. There are two interfaces between each leaf-spine pair. There are four interfaces  between leafs and the TGN. The mapping between the devices in SIM config file and Topology file is described below. 

The following device mapping is typically used:

```
SD1  ==> D1 ==> spine0
SD2  ==> D2 ==> spine1
SD3  ==> D3 ==> leaf0
SD4  ==> D4 ==> leaf1
ixia ==> T1 ==> T1
```

## A Note For Engineers

The tests written here MUST work for both flat-numbered port named and hierarchical port named devices. The tests written however need to be oblivious to the numbering scheme used by the SKU.

The engineers are mandated to use numbering scheme agnostic names in all the tests and config template files. It is mandatory for the reviewers to enforce this.

## Numbering Scheme Agnostic Naming

The interface names are typically identified by the following formula:

(src node)(dst node)(port number between these devices as seen on src node)

For example, "D1D3P1" identifies the first port (P1) on src node (D1) connected to dst node (D2).

More examples are in this topology file :

```spytest_tb_files/tortuga_spytest_topo_4D_ixia_mathilda.yaml```

In the template files, engineers are mandatorily required to use the interface name following the scheme above.

In the test code, engineers are mandatorily required to use the same names off of testbed vars.

Please refer to the existing template and source code to understand the usage. A sample template config file can be found here:
```
sonic-mgmt/spytest/tests/cisco/tortuga/vxlan/vxlan_l2vni_config_template.yaml
```

## Tests

This section describes the steps involved in setting up the pyvxr spytest environment and running the tests.

### Bring up SIM

Bring up SIM and gather port information (cmono)

```
vxr start <sonic-test_path>/pyvxr_yaml_files/tortuga_spytest_5D_linux_ixia_cmono.yaml

vxr vxr.py ports
```

### Setup IXIA

Connect to sonic-mgmt vm, setup the IXIA VM:
```
scp sonic@10.194.84.241:~/keysight-u18070.tar .
Pass: roZes@123
docker load -i keysight-u18070.tar

git clone https://wwwin-github.cisco.com/whitebox/sonic-test.git
cd sonic-test
git checkout <your branch>
```

### Topology file updates

Update the IP addresses of the nodes (follow the mapping described in the earlier sections). The topology (cmono) file is located here:
```
spytest_tb_files/tortuga_spytest_topo_4D_ixia_cmono.yaml
```

Update the IXIA IP addresses under the TGEN device type:
```
"ixia_chassis": {
    "HostAgent": "172.26.228.188",
    "SimLocalIp": "172.26.228.188",
    "mgmt_ip": "192.168.122.28", ====> ip
    "monitor0": 10097,
    "plugin": "x86_64",
    "redir443": 28933,
    "serial0": 17165
},
"ixia_gui": {
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

docker exec -it ixia_sonic_mgmt bash
cd /data

./bin/spytest --testbed ../spytest_tb_files/tortuga_spytest_topo_5d_ixia.yaml --device-feature-group master --module-init-max-timeout=7200 --tc-max-timeout=7200 /data/tests/cisco/tortuga/vxlan/test_l2vni.py

```

