# Testbed topology

```
                             Linux Host                                         Fanout Switch             DUT
    +---------------------------------------------------------------+          +--------------+     +---------------+
    |       PTF Docker                  Openvswitch                 |          |              |     |               |
    |   +----------------------+      +-------------+               |          |              |     |               |
    |   |                eth0  +------+             +--vlan101--+   |          |         Et1  +-----+ Ethernet0     |
    |   |                eth1  +------+             +--vlan102--|   |          |         Et2  +-----+ Ethernet4     |
    |   |                eth2  +------+             +--vlan103--|   |          |         Et3  +-----+ Ethernet8     |
    |   |                eth3  +------+             +--vlan104--|   |          |         Et4  +-----+ Ethernet12    |
    |   |                eth4  +------+             +--vlan105--|   |          |         Et5  +-----+ Ethernet16    |
    |   |                eth5  +------+             +--vlan106--|   |          |         Et6  +-----+ Ethernet20    |
    |   |                eth6  +------+             +--vlan107--|   |          |         Et7  +-----+ Ethernet24    |
    |   |                eth7  +------+             +--vlan108--|   |          |         Et8  +-----+ Ethernet28    |
    |   |                eth8  +------+             +--vlan109--|   |          |         Et9  +-----+ Etherent32    |
    |   |                eth9  +------+             +--vlan110--|   |          |         Et10 +-----+ Ethernet36    |
    |   |                eth10 +------+             +--vlan111--|   |          |         Et11 +-----+ Ethernet40    |
    |   |                eth11 +------+             +--vlan112--|   |          |         Et12 +-----+ Ethernet44    |
    |   |                eth12 +------+             +--vlan113--|   |          |         Et13 +-----+ Ethernet48    |
    |   |                eth13 +------+             +--vlan114--|   |          |         Et14 +-----+ Ethernet52    |
    |   |                eth14 +------+             +--vlan115--|   |          |         Et15 +-----+ Ethernet56    |
    |   |                eth15 +------+             +--vlan116--+---+-- eth0 --+ Et33    Et16 +-----+ Ethernet60    |
    |   |                eth16 +------+             +--vlan117--|   |          |         Et17 +-----+ Ethernet64    |
    |   |                eth17 +------+             +--vlan118--|   |          |         Et18 +-----+ Ethernet68    |
    |   |                eth18 +------+             +--vlan119--|   |          |         Et19 +-----+ Ethernet72    |
    |   |                eth19 +------+             +--vlan120--|   |          |         Et20 +-----+ Ethernet76    |
    |   |                eth20 +------+             +--vlan121--|   |          |         Et21 +-----+ Ethernet80    |
    |   |                eth21 +------+             +--vlan122--|   |          |         Et22 +-----+ Ethernet84    |
    |   |                eth22 +------+             +--vlan123--|   |          |         Et23 +-----+ Ethernet88    |
    |   |                eth23 +------+             +--vlan124--|   |          |         Et24 +-----+ Ethernet92    |
    |   |                eth24 +------+             +--vlan125--|   |          |         Et25 +-----+ Ethernet96    |
    |   |                eth25 +------+             +--vlan126--|   |          |         Et26 +-----+ Ethernet100   |
    |   |                eth26 +------+             +--vlan127--|   |          |         Et27 +-----+ Ethernet104   |
    |   |                eth27 +------+             +--vlan128--|   |          |         Et28 +-----+ Ethernet108   |
    |   |                eth28 +------+             +--vlan129--|   |          |         Et29 +-----+ Ethernet112   |
    |   |                eth29 +------+             +--vlan130--|   |          |         Et30 +-----+ Ethernet116   |
    |   |                eth30 +------+             +--vlan131--|   |          |         Et31 +-----+ Ethernet120   |
    |   |                eth31 +------+             +--vlan132--+   |          |         Et32 +-----+ Ethernet124   |
    |   +----------------------+      +-------------+               |          |              |     |               |
    |                                                               |          |              |     |               |
    +---------------------------------------------------------------+          +--------------+     +---------------+
```
Figure 1: PTF container testbed

- *PTF docker*: A docker container that has 32 ports with pre-installed PTF tools. See https://github.com/Azure/sonic-buildimage/tree/master/dockers/docker-ptf
- *Vlan ports*: 32 vlan ports are created on top of physical port, e.g., eth0, inside the Linux host
- *Openvswitch*: Connect 32 vlan ports to the 32 docker ports inside the Linux host. Openvswitch forwards the packet to the corresponding output port based on the incoming port. No L2/L3 forwarding is enabled in the Openvswitch.
- *Fanout switch*: A physical switch which enables VLAN trunking. Et33 is a vlan trunking port and is connected to the eth0 port of the linux host. Et1-Et32 are vlan access ports and are connect to DUT.

```
                             Linux Host                                         Fanout Switch             DUT
    +---------------------------------------------------------------+          +--------------+     +---------------+
    |                                   Openvswitch                 |          |              |     |               |
    |   +----------------------+      +-------------+               |          |              |     |               |
    |   |   VM_1         eth0  +------+             +--vlan101--+   |          |         Et1  +-----+ Ethernet0     |
    |   +----------------------+      +-------------|           |   |          |              |     |               |
    |   |   VM_2         eth0  +------+             +--vlan102--+   |          |         Et2  +-----+ Ethernet4     |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_3         eth0  +------+             +--vlan103--|   |          |         Et3  +-----+ Ethernet8     |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_4         eth0  +------+             +--vlan104--|   |          |         Et4  +-----+ Ethernet12    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_5         eth0  +------+             +--vlan105--|   |          |         Et5  +-----+ Ethernet16    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_6         eth0  +------+             +--vlan106--|   |          |         Et6  +-----+ Ethernet20    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_7         eth0  +------+             +--vlan107--|   |          |         Et7  +-----+ Ethernet24    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_8         eth0  +------+             +--vlan108--|   |          |         Et8  +-----+ Ethernet28    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_9         eth0  +------+             +--vlan109--|   |          |         Et9  +-----+ Etherent32    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_10        eth0  +------+             +--vlan110--|   |          |         Et10 +-----+ Ethernet36    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_11        eth0  +------+             +--vlan111--|   |          |         Et11 +-----+ Ethernet40    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_12        eth0  +------+             +--vlan112--|   |          |         Et12 +-----+ Ethernet44    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_13        eth0  +------+             +--vlan113--|   |          |         Et13 +-----+ Ethernet48    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_14        eth0  +------+             +--vlan114--|   |          |         Et14 +-----+ Ethernet52    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_15        eth0  +------+             +--vlan115--|   |          |         Et15 +-----+ Ethernet56    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_16        eth0  +------+             +--vlan116--+---+-- eth0 --+ Et33    Et16 +-----+ Ethernet60    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_17        eth0  +------+             +--vlan117--|   |          |         Et17 +-----+ Ethernet64    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_18        eth0  +------+             +--vlan118--|   |          |         Et18 +-----+ Ethernet68    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_19        eth0  +------+             +--vlan119--|   |          |         Et19 +-----+ Ethernet72    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_20        eth0  +------+             +--vlan120--|   |          |         Et20 +-----+ Ethernet76    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_21        eth0  +------+             +--vlan121--|   |          |         Et21 +-----+ Ethernet80    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_22        eth0  +------+             +--vlan122--|   |          |         Et22 +-----+ Ethernet84    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_23        eth0  +------+             +--vlan123--|   |          |         Et23 +-----+ Ethernet88    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_24        eth0  +------+             +--vlan124--|   |          |         Et24 +-----+ Ethernet92    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_25        eth0  +------+             +--vlan125--|   |          |         Et25 +-----+ Ethernet96    |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_26        eth0  +------+             +--vlan126--|   |          |         Et26 +-----+ Ethernet100   |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_27        eth0  +------+             +--vlan127--|   |          |         Et27 +-----+ Ethernet104   |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_28        eth0  +------+             +--vlan128--|   |          |         Et28 +-----+ Ethernet108   |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_29        eth0  +------+             +--vlan129--|   |          |         Et29 +-----+ Ethernet112   |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_30        eth0  +------+             +--vlan130--|   |          |         Et30 +-----+ Ethernet116   |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_31        eth0  +------+             +--vlan131--|   |          |         Et31 +-----+ Ethernet120   |
    |   +----------------------+      |-------------|           |   |          |              |     |               |
    |   |   VM_32        eth0  +------+             +--vlan132--+   |          |         Et32 +-----+ Ethernet124   |
    |   +----------------------+      +-------------+               |          |              |     |               |
    |                                                               |          |              |     |               |
    +---------------------------------------------------------------+          +--------------+     +---------------+
```
Figure 2: VM set testbed

## Requirenments for the Linux Host
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
up ip link set p4p1 up
```

### Deploy testbed with one VM set
1. clone sonic-mgmt repo to local directory
2. Edit 'ansible/veos' file. Put ip address of your server after 'ansible_host='
3. Edit 'ansible/group_vars/vm_host'. Put your credentials to reach the server
4. Check, that you can reach the server by running command 'ansible -i veos -m ping vm_host_1' from ansible directory. The output should contain 'pong'
5. Edit 'ansible/group_vars/vm_host/main.yml'. 
   * 'root_path': path where VMs virtual disks resides
   * 'vm_images_url': URL where VM images could be downloaded
   * 'cd_image_filename': filename of cd image of veos
   * 'hdd_image_filename': filename of hdd image of veos
   * 'http_proxy': your http_proxy
   * 'http_proxy': your https_proxy
6. Edit 'ansible/host_vars/SERV-01.yml'. It contains settings for SERV-01. SERV-02 contains similar settings which are applied to SERV-02
   * 'mgmt_gw': ip address of gateway for management interfaces of VM. See 3.2
   * 'vm_X_enabled': true, if you want to run X vm set
   * 'vm_X_external_iface': name of interface which connected to DUT. See 3.3
   * 'vm_X_vlan_base': vlan number which is used for connection to first port of DUT.
7. Edit 'ansible/vars/configurations/*.yml' files. You need to adjust 'minigraph_mgmt_interface' to settings of your network See 3.2
8. Start testbed with command 'ANSIBLE_SCP_IF_SSH=y ansible-playbook -i veos start_vm_sets.yml --limit server_1 -e vm_set_1=true'
9. Stop testbed with command 'ANSIBLE_SCP_IF_SSH=y ansible-playbook -i veos stop_vm_sets.yml --limit server_1 -e vm_set_1=true'
