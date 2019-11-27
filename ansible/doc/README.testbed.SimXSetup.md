# Testbed Setup

This document describes the steps to setup the SimX in docker based testbed and deploy a topology. Mellanox only provides the simulator to it's customers. 

## About SimX

SimX is a functional simulation of Mellanox PCI devices
 - It simulates 
   - Mellanox NICs
   - Switch: Spectrum-1, Spectrum-2, Spectrum-3
- It simulates both FW and HW
- All flows are supported (controll + data path)

- Inside the VM, the OS is runnaing as is
  - Running Mellanox SAI
  - Running Mellanox SDK


## Prepare testbed server

- Install Ubuntu 18.04 amd64 server. To setup a T0 topology, the server needs to have 10GB free memory.
- Install bridge utils

```
$ sudo apt-get install bridge-utils
```

- Setup internal management network.

```
$ sudo brctl addbr br0
$ sudo ifconfig br0 10.250.0.1/24
$ sudo ifconfig br0 up
```

- Download vEOS image from [arista](https://www.arista.com/en/support/software-download).
- Copy below image files to ```~/veos-vm/images``` on your testbed server.
   - ```Aboot-veos-serial-8.0.0.iso```
   - ```vEOS-lab-4.15.9M.vmdk```

## Setup docker registry for *PTF* docker

Instructions to build or download pre-built docker-ptf [here](https://github.com/Azure/sonic-mgmt/blob/master/ansible/doc/README.testbed.VsSetup.md#setup-docker-registry-for-ptf-docker)

## Build or download *sonic-mgmt* docker image

Instructions to set up sonic-mgmt docker [here](https://github.com/Azure/sonic-mgmt/blob/master/ansible/doc/README.testbed.VsSetup.md#build-or-download-sonic-mgmt-docker-image)

## Download SimX in Docker  

- Download the SimX in Docker archive. Mellanox only provides it to it's customers. You need to contact the support team to get it.

- unzip the archive into ```~/sid/images/```

```
$ mkdir -p ~/sid/images
$ unzip simxindocker.gz
$ mv simixindocker/* ~/sid/images/
```

You should get something like:
```
|-- sid
|   |-- images
|   |   |-- settings.ini     - input values for start.py(SimX in Docker infra)
|   |   |-- simx.tar         - docker image of SimX in Docker
|   |   |-- sonic_spc.img   - vm disk image for the simx-qemu emulator
|   |   `-- start.py         - script to start the simulator inside dcoker container(SiD infra)
```

```settings.ini``` file 

```
[vlab-simx-01]
chip = spectrum
vm_image = ~/sid/disks/vlab-simx-01.img
ip =  10.250.0.103, 255.255.255.0, 10.250.0.1
```

You can execute ```./start.py``` to start one docker container, without applying a topology.

## Load the docker image

```
$ docker load -i simx.tar
```

## Clone sonic-mgmt repo

```
$ git clone https://github.com/Azure/sonic-mgmt
```

### Modify sonic-mgmt

Add host_vars file for the hypervisor

ansible/host_vars/<HYPERVISOR_HOSTNAME>.yml:
```
mgmt_bridge: br0
mgmt_prefixlen: 24
mgmt_gw: 10.250.0.1
vm_mgmt_gw: 10.250.0.1

internal_mgmt_port: True
```

Change the veos.vtb:

```
[vm_host_1]
<HYPERVISOR_HOSTNAME> ansible_host=<HYPERVISOR_IP> ansible_user=<use_own_value>

[vm_host:children]
vm_host_1

[vms_1]
VM0100 ansible_host=10.250.0.51
VM0101 ansible_host=10.250.0.52
VM0102 ansible_host=10.250.0.53
VM0103 ansible_host=10.250.0.54


[eos:children]
vms_1

## The groups below are helper to limit running playbooks to server_1, server_2 or server_3 only
[server_1:children]
vm_host_1
vms_1

[server_1:vars]
host_var_file=host_vars/<HYPERVISOR_HOSTNAME>.yml

[servers:children]
server_1

[servers:vars]
topologies=['t1', 't1-lag', 't1-64-lag', 't1-64-lag-clet', 't0', 't0-16', 't0-56', 't0-52', 'ptf32', 'ptf64', 't0-64', 't0-64-32', 't0-116']

[sonic]
vlab-01 ansible_host=10.250.0.101 type=kvm hwsku=Force10-S6000
vlab-02 ansible_host=10.250.0.102 type=kvm hwsku=Force10-S6100
vlab-simx-01 ansible_host=10.250.0.103 type=simx hwsku=MSN2700
```

Notice the _type=simx_ for the SimX device

Add entry in vtestbed.csv

```
# conf-name,group-name,topo,ptf_image_name,ptf_ip,server,vm_base,dut,comment
vms-kvm-t0,vms6-1,t0,docker-ptf-brcm,10.250.0.102/24,server_1,VM0100,vlab-01,Tests virtual switch vm
vms-kvm-t0-64,vms6-1,t0-64,docker-ptf-brcm,10.250.0.102/24,server_1,VM0100,vlab-02,Tests virtual switch vm
vms-kvm-t0,vms6-1,t0,docker-ptf-brcm,10.250.0.102/24,server_1,VM0100,vlab-simx-01,Tests virtual SimX vm
```

## Run sonic-mgmt docker

```
$ docker run -v $PWD:/data -it docker-sonic-mgmt bash
```

From now on, all steps are running inside the *sonic-mgmt* docker.

## Setup Arista VMs in the server and deploy the topology

```
$ ./testbed-cli.sh -m veos.vtb start-vms server_1 password.txt

$ ./testbed-cli.sh -t vtestbed.csv -m veos.vtb add-topo vms-kvm-t0 password.txt
```

## Verify the simulator running in the container(optional)

```
docker ps
CONTAINER ID        IMAGE                                          COMMAND                  CREATED             STATUS              PORTS               NAMES
3fb6b04aa28f        arc-build-server:5000/docker-ptf-mlnx:latest   "/usr/local/bin/supe…"   5 hours ago         Up 5 hours                              ptf_vms6-2
be00ad20b505        simx                                           "/usr/sbin/init"         5 hours ago         Up 5 hours                              
vlab-simx-01
```

Grep for the simulator process

```
root@dev-r-vrt-232:/images# docker exec be00ad20b505 ps aux | grep simx-qemu-system-x86_64 
root      1144  160 21.7 24598832 7151752 ?    Sl   07:45 464:30 /opt/simx/bin/simx-qemu-system-x86_64
```

## Deploy minigraph on the DUT

```
$ ./testbed-cli.sh -t vtestbed.csv -m veos.vtb deploy-mg vms-kvm-t0 lab password.txt
```

You should be login into the SimX vm using IP: 10.250.0.103 using admin:YourPaSsWoRd.
There is also a telnet connection: 

```
$ telnet localhost 1213
```

You should see BGP sessions up in SONiC.

```
admin@vlab-simx-01:~$ show ip bgp sum
BGP router identifier 10.1.0.32, local AS number 65100
RIB entries 12807, using 1401 KiB of memory
Peers 8, using 36 KiB of memory
Peer groups 2, using 112 bytes of memory

Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.57       4 64600    3208      12        0    0    0 00:00:22     6400
10.0.0.59       4 64600    3208     593        0    0    0 00:00:22     6400
10.0.0.61       4 64600    3205     950        0    0    0 00:00:21     6400
10.0.0.63       4 64600    3204     950        0    0    0 00:00:21     6400
```
At this point the DUT is ready to run some tests.

## Troubleshooting

Useful log files:
If something went wrong during container startup:
~/sid/images/autostart_<container_name>.log

If something went wrong with the simulator:
(in docker) /var/log/libvirt/qemu/d-switch-001.log

No ssh connectivity to the VM - try ```telnet <hypervisor_ip> 1213```
