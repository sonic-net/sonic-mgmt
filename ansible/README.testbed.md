# Requirements for the Linux Host
1. Ubuntu 16.04 x64
2. Installed docker-engine and python (ansible requires python 2.7)
3. Three network cards:
  1. first is used for the server management
  2. second is used to connect management interfaces of VMs and docker containers to a network.
  3. third is used to connect VMs and ptf containers to DUTs frontal panel ports

Content of /etc/network/interfaces:
```
root@STR-AZURE-SERV-01:~# cat /etc/network/interfaces
# The primary network interface - testbed server management
auto em1
iface em1 inet static
        address 10.250.0.245
        netmask 255.255.255.0
        network 10.250.0.0
        broadcast 10.250.0.255
        gateway 10.250.0.1
        dns-nameservers 10.250.0.1 10.250.0.2
        # dns-* options are implemented by the resolvconf package, if installed
        dns-search SOMECOMPANY

# VM and dockers management interfaces
auto br1
iface br1 inet manual
    bridge_ports em2
    bridge_stp off
    bridge_maxwait 0
    bridge_fd 0

# DUTs frontpanel ports
auto p4p1
iface p4p1 inet manual
  mtu 9216
up ip link set p4p1 up
```

# SONiC testbed physical topology

![](img/testbed.png)

1. Every DUT port is connected to one of leaf fanout switches
2. Every leaf fanout switch has unique vlan tag for every DUT port
3. Root fanout switch connects leaf fanout switches and testbed servers
4. Connections from root fanout switches are 802.1Q trunks
5. Any testbed server can access any DUT port by sending a packet with the port vlan tag (root fanout switch should have this vlan number enabled on the server trunk)

# Testbed server connections

![](img/testbed-server.png)

1. The testbed server has 3 network ports:
  1. Trunk port to root fanout switch
  2. Server management port to manage the server
  3. Testbed management port to manage VMs and PTFs containers on the server
2. VMs are created right after the server starts
3. VMs connections and PTF containers are created when a new topology is being added

# Topologies

1. Configuration of a testbed topology is defined in one file: testbed.csv
2. One script to operate all testbeds: testbed-cli.sh
3. Flexible topologies which allow to use vm_set and ptf container as one entity
4. All VM management ip information in one place: veos inventory file
5. ptf container is generalized and used in every topology
6. Automatic provisioning of fanout switch configuration (should be refactored)
7. Every VM uses 2G of RAM

# Testbed topology configuration

1. One entry in testbed.csv
2. Consist of:
  1. physical topology: How ports of VMs and ptf connected to DUT
  2. configuration templates for VMs
3. Defined in vars/topo_*.yml files
4. Current topologies are:
  1. t1: 32 VMs + ptf container for injected ports
  2. t1-lag: 24 VMs + ptf container for injected ports. 8 VMs has two ports each in LAG
  3. ptf32: classic ptf container with 32 ports connected directly to DUT ports
  4. ptf64: as ptf32, but with 64 ports
  5. t0: 4 VMs + ptf. ptf container has 4 injected ports + 28 directly connected ports

# testbed.csv
```
# conf-name,group-name,topo,ptf_image_name,ptf_mgmt_ip,server,vm_base,dut,comment
ptf1-m,ptf1,ptf32,docker-ptf-sai-mlnx,10.255.0.188/24,server_1,,str-msn2700-01,Tests ptf
vms-t1,vms1-1,t1,docker-ptf-sai-mlnx,10.255.0.178/24,server_1,VM0100,str-msn2700-01,Tests vms
vms-t1-lag,vms1-1,t1-lag,docker-ptf-sai-mlnx,10.255.0.178/24,server_1,VM0100,str-msn2700-01,Tests vms

```

1. uniq-name - to address row in table
2. testbed-name – used in interface names, up to 8 characters
3. topo – name of topology
4. ptf_imagename – defines ptf image
5. ptf_mgmt_ip – ip address for mgmt interface of ptf container
6. server – server where the testbed resides
7. vm_base – first VM for the testbed. If empty, no VMs are used
8. DUT – target dut name
9. Comment – any text here

# testbed-cli.sh

1. Maintenance purposes only
 - ./testbed-cli.sh start-vms {server_name} ~./password   # after a server restarted
 - ./testbed-cli.sh stop-vms {server_name} ~./password    # before a server restarted
2. General usage
 - ./testbed-cli.sh add-topo {topo_name} ~./password      # create topo with name {topo_name} from testbed.csv
 - ./testbed-cli.sh remove-topo {topo_name} ~./password   # destroy topo with name {topo_name} from testbed.csv
 - ./testbed-cli.sh renumber-topo {topo_name} ~./password # renumber topo with name {topo_name} from testbed.csv

# Current topologies

## t1

![](img/testbed-t1.png)

 - Requires 32 VMs
 - All DUT ports are connected to VMs
 - PTF container has injected ports only

## t1-lag

![](img/testbed-t1-lag.png)

 - Requires 24 VMs
 - All DUT ports are connected to VMs
 - PTF container has injected ports only

## ptf32

![](img/testbed-ptf32.png)

 - Requires 0 VMs
 - All DUT ports are directly connected to PTF container
 - PTF container has no injected ports

## ptf64

![](img/testbed-ptf64.png)

 - Requires 0 VMs
 - All DUT ports are directly connected to PTF container
 - PTF container has no injected ports

## t0

![](img/testbed-t0.png)

 - Requires 4 VMs
 - 4 DUT ports are connected to VMs
 - PTF container has 4 injected ports and 28 directly connected ports

# PTF Testbed topology
```
Figure 1: PTF container testbed

- *PTF docker*: A docker container that has 32 ports with pre-installed PTF tools. See https://github.com/Azure/sonic-buildimage/tree/master/dockers/docker-ptf
- *Vlan ports*: 32 vlan ports are created on top of a physical port, e.g., eth0, inside the Linux host. After creation the vlan ports are injected directly to a ptf docker host.
- *Fanout switch*: A physical switch which enables VLAN trunking.
   * Et33 is a vlan trunking port and is connected to the eth0 port of the linux host.
   * Et1-Et32 are vlan access ports and are connect to DUT.
   * Enable LACP/LLDP passthrough
   * Disable spanning tree protocol

### Deploy testbed with one ptf container
1. clone sonic-mgmt repo to local directory
2. Edit 'ansible/group_vars/vm_host'. Put your credentials to reach the server
3. Check, that you can reach the server by running command 'ansible -i veos -m ping vm_host_1' from ansible directory. The output should contain 'pong'
4. Edit 'ansible/group_vars/vm_host/main.yml'. 
   * 'http_proxy': your http_proxy
   * 'http_proxy': your https_proxy
5. Edit 'ansible/host_vars/STR-ACS-SERV-01.yml'. It contains settings for STR-ACS-SERV-01. STR-ACS-SERV-02 contains similar settings which are applied to STR-ACS-SERV-02
   * 'mgmt_gw': ip address of gateway for management interfaces of ptf_container
   * 'mgmt_bridge': the bridge which is used to connect the management network
   * 'externel_iface': the interface which is connected to the fanout switch
   * 'ptf_X_enabled': true, if you want to run X ptf container
   * 'ptf_X_mgmt_ip': which ip is used inside of the container for the management network
   * 'ptf_X_vlan_base': vlan number which is used for connection to first port of DUT
7. Edit 'ansible/vars/docker_registry.yml'. You need put your docker registry server here
8. Start ptf container with command 'ansible-playbook -i veos start_ptf_containers.yml --vault-password-file=~/.password --limit server_1 -e ptf_1=true'. See start_ptf_containers.yml for more examples
9. Stop ptf container with command 'ansible-playbook -i veos stop_ptf_containers.yml --vault-password-file=~/.password --limit server_1 -e ptf_1=true'. See stop_ptf_containers.yml for more examples


# VM set testbed topology

```
                              Linux Host                                     Fanout              DUT
                                                                             Switch
 +-------------------------------------------------------------+          +----------+     +-------------+
 |  PTF Docker        VM sets             Ovs                  |          |          |     |             |
 |               +--------------+      +-------+               |          |          |     |             |
 |  +---------+  | VM_1    eth0 +------+       +--vlan101--+   |          |     Et1  +-----+ Ethernet0   |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth0  +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_2    eth0 +------+       +--vlan102--+   |          |     Et2  +-----+ Ethernet4   |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth1  +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_3    eth0 +------+       +--vlan103--+   |          |     Et3  +-----+ Ethernet8   |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth2  +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_4    eth0 +------+       +--vlan104--+   |          |     Et4  +-----+ Ethernet12  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth3  +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_5    eth0 +------+       +--vlan105--+   |          |     Et5  +-----+ Ethernet16  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth4  +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_6    eth0 +------+       +--vlan106--+   |          |     Et6  +-----+ Ethernet20  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth5  +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_7    eth0 +------+       +--vlan107--+   |          |     Et7  +-----+ Ethernet24  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth6  +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_8    eth0 +------+       +--vlan108--+   |          |     Et8  +-----+ Ethernet28  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth7  +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_9    eth0 +------+       +--vlan109--+   |          |     Et9  +-----+ Etherent32  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth8  +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_10   eth0 +------+       +--vlan110--+   |          |     Et10 +-----+ Ethernet36  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth9  +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_11   eth0 +------+       +--vlan111--+   |          |     Et11 +-----+ Ethernet40  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth10 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_12   eth0 +------+       +--vlan112--+   |          |     Et12 +-----+ Ethernet44  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth11 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_13   eth0 +------+       +--vlan113--+   |          |     Et13 +-----+ Ethernet48  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth12 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_14   eth0 +------+       +--vlan114--+   |          |     Et14 +-----+ Ethernet52  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth13 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_15   eth0 +------+       +--vlan115--+   |          |     Et15 +-----+ Ethernet56  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth14 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_16   eth0 +------+       |           |   |          |     Et16 +-----+ Ethernet60  |
 |  |         |  +--------------+      |       +--vlan116--+---+-- eth0 --+ Et33     |     |             |
 |  |   eth15 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_17   eth0 +------+       +--vlan117--+   |          |     Et17 +-----+ Ethernet64  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth16 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_18   eth0 +------+       +--vlan118--+   |          |     Et18 +-----+ Ethernet68  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth17 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_19   eth0 +------+       +--vlan119--+   |          |     Et19 +-----+ Ethernet72  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth18 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_20   eth0 +------+       +--vlan120--+   |          |     Et20 +-----+ Ethernet76  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth19 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_21   eth0 +------+       +--vlan121--+   |          |     Et21 +-----+ Ethernet80  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth20 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_22   eth0 +------+       +--vlan122--+   |          |     Et22 +-----+ Ethernet84  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth21 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_23   eth0 +------+       +--vlan123--+   |          |     Et23 +-----+ Ethernet88  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth22 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_24   eth0 +------+       +--vlan124--+   |          |     Et24 +-----+ Ethernet92  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth23 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_25   eth0 +------+       +--vlan125--+   |          |     Et25 +-----+ Ethernet96  |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth24 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_26   eth0 +------+       +--vlan126--+   |          |     Et26 +-----+ Ethernet100 |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth25 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_27   eth0 +------+       +--vlan127--+   |          |     Et27 +-----+ Ethernet104 |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth26 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_28   eth0 +------+       +--vlan128--+   |          |     Et28 +-----+ Ethernet108 |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth27 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_29   eth0 +------+       +--vlan129--+   |          |     Et29 +-----+ Ethernet112 |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth28 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_30   eth0 +------+       +--vlan130--+   |          |     Et30 +-----+ Ethernet116 |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth29 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_31   eth0 +------+       +--vlan131--+   |          |     Et31 +-----+ Ethernet120 |
 |  |         |  +--------------+      |       |           |   |          |          |     |             |
 |  |   eth30 +------------------------+       |           |   |          |          |     |             |
 |  |         |  +--------------+      +-------|           |   |          |          |     |             |
 |  |         |  | VM_32   eth0 +------+       +--vlan132--+   |          |     Et32 +-----+ Ethernet124 |
 |  |         |  +--------------+      +       |               |          |          |     |             |
 |  |   eth31 +------------------------+       |               |          |          |     |             |
 |  |         |                        +-------|               |          |          |     |             |
 |  |---------+                                                |          |          |     |             |
 +-------------------------------------------------------------+          +----------+     +-------------+
```
Figure 2: VM set testbed with injected PTF docker

In this testbed, we have 32 VMs and 1 PTF docker. The VMs use Arista vEOS. Each VM has 10 network interfaces:
 1. 8 front panel ports. These ports are connected to openvswitch bridges, which are connected to vlan interfaces. The vlan interfaces are connected to the fanout switch (through physical port).
 2. 1 back panel port. All testbed VMs connected to each other using this port (it isn't shown on the figure above).
 3. 1 management port. This port is used to connect to the VMs

The ptf docker container connects to the bridges which connect the VMs frontpanel ports and physical vlans. Each bridge has three ports:
 1. Frontpanel port from a VM
 2. Physical vlan port
 3. PTF container port

Packets coming from the physical vlan interface are sent to both the VMs and the PTF docker. Packets from the VM and PTF docker are
sent to the vlan interface. It allows us to inject packets from the PTF host to DUT and maintain a BGP session between VM and DUT at the same time.

### Deploy testbed with one VM set
1. clone sonic-mgmt repo to local directory
2. Edit 'ansible/veos' file. Put ip address of your server after 'ansible_host='
3. Edit 'ansible/group_vars/eos/eos.yml' file. Put your internal snmp community string after 'snmp_rocommunity:'.
4. Edit 'ansible/group_vars/vm_host'. Put your credentials to reach the server
5. Check, that you can reach the server by running command 'ansible -i veos -m ping vm_host_1' from ansible directory. The output should contain 'pong'
6. Edit 'ansible/group_vars/vm_host/main.yml'. 
   * 'root_path': path where VMs virtual disks resides
   * 'vm_images_url': URL where VM images could be downloaded
   * 'cd_image_filename': filename of cd image of veos
   * 'hdd_image_filename': filename of hdd image of veos
   * 'http_proxy': your http_proxy
   * 'http_proxy': your https_proxy
7. Edit 'ansible/host_vars/STR-ACS-SERV-01.yml'. It contains settings for STR-ACS-SERV-01. STR-ACS-SERV-02 contains similar settings which are applied to STR-ACS-SERV-02
   * 'mgmt_gw': ip address of gateway for management interfaces of VM. See 3.2
   * 'vm_X_enabled': true, if you want to run X vm set
   * 'vm_X_vlan_base': vlan number which is used for connection to first port of DUT.
   * 'vlans': list of vlan offsets for the VM FP ports. For example: if vlans equal to "5,6" it means that the VM frontpanel port 0 will be connected to vlan {{ vm_X_vlan_base + 5 - 1 }} and VM frontpanel port 1 will be connected to vlan {{ vm_X_vlan_base + 6 - 1 }}
8. Edit 'ansible/minigraph/*.xml' files. You need to adjust following xml nodes to settings of your network:
   * DeviceMiniGraph/DpgDec/DeviceDataPlaneInfo/ManagementIPInterfaces/ManagementIPInterface/Prefix/IPPrefix
   * DeviceMiniGraph/DpgDec/DeviceDataPlaneInfo/ManagementIPInterfaces/ManagementIPInterface/PrefixStr
9. Start testbed with command 'ANSIBLE_SCP_IF_SSH=y ansible-playbook -i veos start_vm_sets.yml --limit server_1 -e vm_set_1=true'
10. Stop testbed with command 'ANSIBLE_SCP_IF_SSH=y ansible-playbook -i veos stop_vm_sets.yml --limit server_1 -e vm_set_1=true'
