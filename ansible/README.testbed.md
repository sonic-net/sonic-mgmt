# Requirements for the Linux Host
1. Ubuntu 16.04 x64
2. Installed docker-engine
3. Three network cards:
  1. first is used for the server management
  2. second is used to connect management interfaces of VMs and docker containers to network.
  3. third is used to connect VMs and ptf containers to DUTs

Content of /etc/network/interfaces:
```
root@STR-AZURE-SERV-02:~# cat /etc/network/interfaces
# The primary network interface
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

auto br1
iface br1 inet manual
    bridge_ports em2
    bridge_stp on
    bridge_maxwait 0
    bridge_fd 0

auto p4p1
iface p4p1 inet manual
  mtu 9216
up ip link set p4p1 up
```


# PTF Testbed topology

```
             Linux Host                                         Fanout Switch             DUT
    +----------------------------------------------+          +--------------+     +---------------+
    |       PTF Docker                             |          |              |     |               |
    |   +----------------------+                   |          |              |     |               |
    |   |                eth0  +------vlan101--+   |          |         Et1  +-----+ Ethernet0     |
    |   |                eth1  +------vlan102--|   |          |         Et2  +-----+ Ethernet4     |
    |   |                eth2  +------vlan103--|   |          |         Et3  +-----+ Ethernet8     |
    |   |                eth3  +------vlan104--|   |          |         Et4  +-----+ Ethernet12    |
    |   |                eth4  +------vlan105--|   |          |         Et5  +-----+ Ethernet16    |
    |   |                eth5  +------vlan106--|   |          |         Et6  +-----+ Ethernet20    |
    |   |                eth6  +------vlan107--|   |          |         Et7  +-----+ Ethernet24    |
    |   |                eth7  +------vlan108--|   |          |         Et8  +-----+ Ethernet28    |
    |   |                eth8  +------vlan109--|   |          |         Et9  +-----+ Etherent32    |
    |   |                eth9  +------vlan110--|   |          |         Et10 +-----+ Ethernet36    |
    |   |                eth10 +------vlan111--|   |          |         Et11 +-----+ Ethernet40    |
    |   |                eth11 +------vlan112--|   |          |         Et12 +-----+ Ethernet44    |
    |   |                eth12 +------vlan113--|   |          |         Et13 +-----+ Ethernet48    |
    |   |                eth13 +------vlan114--|   |          |         Et14 +-----+ Ethernet52    |
    |   |                eth14 +------vlan115--|   |          |         Et15 +-----+ Ethernet56    |
    |   |                eth15 +------vlan116--+---+-- eth0 --+ Et33    Et16 +-----+ Ethernet60    |
    |   |                eth16 +------vlan117--|   |          |         Et17 +-----+ Ethernet64    |
    |   |                eth17 +------vlan118--|   |          |         Et18 +-----+ Ethernet68    |
    |   |                eth18 +------vlan119--|   |          |         Et19 +-----+ Ethernet72    |
    |   |                eth19 +------vlan120--|   |          |         Et20 +-----+ Ethernet76    |
    |   |                eth20 +------vlan121--|   |          |         Et21 +-----+ Ethernet80    |
    |   |                eth21 +------vlan122--|   |          |         Et22 +-----+ Ethernet84    |
    |   |                eth22 +------vlan123--|   |          |         Et23 +-----+ Ethernet88    |
    |   |                eth23 +------vlan124--|   |          |         Et24 +-----+ Ethernet92    |
    |   |                eth24 +------vlan125--|   |          |         Et25 +-----+ Ethernet96    |
    |   |                eth25 +------vlan126--|   |          |         Et26 +-----+ Ethernet100   |
    |   |                eth26 +------vlan127--|   |          |         Et27 +-----+ Ethernet104   |
    |   |                eth27 +------vlan128--|   |          |         Et28 +-----+ Ethernet108   |
    |   |                eth28 +------vlan129--|   |          |         Et29 +-----+ Ethernet112   |
    |   |                eth29 +------vlan130--|   |          |         Et30 +-----+ Ethernet116   |
    |   |                eth30 +------vlan131--|   |          |         Et31 +-----+ Ethernet120   |
    |   |                eth31 +------vlan132--+   |          |         Et32 +-----+ Ethernet124   |
    |   +----------------------+                   |          |              |     |               |
    |                                              |          |              |     |               |
    +----------------------------------------------+          +--------------+     +---------------+
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
