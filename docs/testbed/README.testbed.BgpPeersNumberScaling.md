# Background and Motivation

When deploy a testbed with a great number of virtual ceos neighbors, we will create ceos containers on same server, however, the server doesn't have infinite resources such as memory to deploy that.

To leverage the servers instead of single server, we proposal this design for deploying testbed with multiple servers.

# Table of Contents
  - [File Content Schema Change](#File-Content-Schema-Change)
    - [testbed.yml](#testbedyml)
    - [topo_*.yml](#topo_yml)
  - [Code Logic Change](#Code-Logic-Change)
    - [Parameters Constrain Validation](#Parameters-Constrain-Validation)
    - [Create 802.1Q VLAN](#Create-8021Q-VLAN)
    - [Create Net and Ceos Containers](#Create-Net-and-Ceos-Containers)
    - [Create PTF Containers](#Create-PTF-Containers)
    - [Network Connection](#Network-Connection)
    - [Automation Script](#Automation-Script)
    - [Changes To Be Determined](#Changes-To-Be-Determined)

# File Content Schema Change

## testbed.yml
To make testbeds can be deployed on multiple servers, we deprecated the previous key "server" and add a new key "servers" with a list of servers for deployment.

### Before
```
- conf-name: testbed-demo
  group-name: tb-1
  topo: t0
  ptf_image_name: ptf-image-lastest
  ptf: ptf-tb-1
  ptf_ip: 1.1.1.1/24
  ptf_ipv6: fec0::1/64
  ptf_extra_mgmt_ip: ["2.1.1.1/17"]
  server: server_1
  vm_base: VM1000
  dut:
    - dut-1
  inv_name: lab_inv
```

### After
When deploy testbed on multiple servers, each server should have one ptf container to provide a environment to run processes like ptf_nn_agent and exbgp. So the ptf container should declare with server.

And because VM hosts in inventory file are children of server and vm_base is related to server, so we declare vm_base with server.

Finally we got a new key "servers" with a list of servers, and each server has its ptf and vm_base declared.

```
- conf-name: testbed-demo
  group-name: tb-1
  topo: t0
  ptf_image_name: ptf-image-lastest
  servers:
    - server_1:
        ptf: ptf-tb-1-1
        ptf_ip: 1.1.1.1/24
        ptf_ipv6: fec0::1/64
        ptf_extra_mgmt_ip: ["2.1.1.1/17"]
        vm_base: VM1000
    - server_2:
        ptf: ptf-tb-1-2
        ptf_ip: 1.1.1.2/24
        ptf_ipv6: fec0::2/64
        ptf_extra_mgmt_ip: ["2.1.1.2/17"]
        vm_base: VM2000
    - server_3:
        ptf: ptf-tb-1-3
        ptf_ip: 1.1.1.3/24
        ptf_ipv6: fec0::3/64
        ptf_extra_mgmt_ip: ["2.1.1.3/17"]
        vm_base: VM3000
  dut:
    - dut-1
  inv_name: lab_inv
```

## topo_*.yml
For distribute interfaces and bgp peers on different servers, we need to know which server to deploy them. So we add a prefix "\<server-index\>," for host_interfaces and VMs' vm_offset to indicate which server the instance should be deployed on.

### Before
```
topology:
  host_interfaces:
    - 0
    - 1
  VMs:
    Peer1:
      vlans:
        - 2
      vm_offset: 0
    Peer2:
      vlans:
        - 3
      vm_offset: 1
    Peer3:
      vlans:
        - 4
      vm_offset: 2
```

### After
For host_interface: 0,0 means the interface 0 should connect to ptf container in server 0 with 8021.Q VLAN.

For vm_offset: 1,0 means we should deploy this VM on server 1 and with host hasing vm_offset 0 as bgp peers.
```
topology:
  host_interfaces:
    - 0,0  # 0,0 means the interface 0 should be deployed on server 0
    - 1,1
  VMs:
    Peer1:
      vlans:
        - 2
      vm_offset: 0,0 # 0,0 means we should deploy this VM on server 0 and with vm_offset 0
    Peer2:
      vlans:
        - 3
      vm_offset: 1,0 # 1,0 means we should deploy this VM on server 1 and with vm_offset 0
    Peer3:
      vlans:
        - 4
      vm_offset: 2,0
```

# Code Logic Change
After schema change, we need to update code to support parsing new schema and do correct works.

## Parameters Constrain Validation
There are some parameters need to be validated before deployment.
1. For topology define for multiple server, if we ref the topo in testbed.yml, we should have equal numer of servers define in testbed.yml or script can't find server with target server index, vice versa.

## Create 802.1Q VLAN
For DUTs' interfaces defined in topology file, we need to make them connect to servers by 802.1Q VLAN, in previous code, we create all 802.1Q VLANs for DUTs on one server. In current design, we will leverage topology file content and graph connection information to create 802.1Q VLAN on multiple servers. Make sure interface is connect to correct server defined in testbed.yml with correct server index defined in topology file.

## Create Net and Ceos Containers
In previous code, we need to create net and ceos containers on single server for each interfaces on dut. In current design, we need to got vm_base defined in testbed.yml and use customed ansible plugin filters to filter out VM host with vm offset defined in topo file for each server, so when running playbook for any server, we will only create necessary net and ceos containers on it.

## Create PTF Containers
In previous code we only create on PTF container for mocking servers and sniff/inject traffic. In current design, every server will has a ptf container for mocking servers and traffic sniffing/injection depends on interface and peers distribution.

## Network Connection
To control traffic follow between ptf, dut and ceos, we need to create OVS bridge for them and setup bridge on every servers.

## Automation Script
To create a topology file with multiple servers, we can write a script to generate all content of inventory, testbed.yml and topology file.

## Changes To Be Determined
1. Routes announcement
1. Topo removement
1. Minigraph deployment
1. ...
