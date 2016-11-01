Requirenments for the server:
1. Ubuntu 16.04 x64
2. Installed docker-engine
3. Three network cards:
  1. first is used for the server management
  2. second is used to connect management interfaces of VMs and docker containers to network.
  3. third is used to connect VMs and ptf containers to DUTs

Content of /etc/network/interfaces:
`
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
`

To deploy testbed with one VM set.
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
