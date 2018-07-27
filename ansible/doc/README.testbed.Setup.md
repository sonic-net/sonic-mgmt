# Testbed Setup

This document describes the steps to setup the testbed and deploy a topology.

## Prepare testbed server

- Install Ubuntu 16.04 or 17.04 amd64 server.
- Setup management port configuration using sample ```/etc/network/interfaces```.

```
root@server-1:~# cat /etc/network/interfaces
# The management network interface
auto ma0
iface ma0 inet manual

# Server, VM and PTF management interface
auto br1
iface br1 inet static
    bridge_ports ma0
    bridge_stp off
    bridge_maxwait 0
    bridge_fd 0
    address 10.250.0.245
    netmask 255.255.255.0
    network 10.250.0.0
    broadcast 10.250.0.255
    gateway 10.250.0.1
    dns-nameservers 10.250.0.1 10.250.0.2
    # dns-* options are implemented by the resolvconf package, if installed
```

- Installed python 2.7 (required by ansible).
- Add Docker's official GPG key
```
   $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
```

## Setup docker registry for *PTF* docker

PTF docker is used to send and receive packets to test data plane. 

- Build PTF docker
```
git clone --recursive https://github.com/Azure/sonic-buildimage.git
make configure PLATFORM=generic
make target/docker-ptf.gz
```

- Setup [docker registry](https://docs.docker.com/registry/) and upload *docker-ptf* to the docker registry.

## Build and run *sonic-mgmt* docker

ansible playbook in *sonic-mgmt* repo requires to setup ansible and various dependencies.
We have built a *sonic-mgmt* docker that installs all dependencies, and you can build 
the docker and run ansible playbook inside the docker.

- Build *sonic-mgmt* docker
```
git clone --recursive https://github.com/Azure/sonic-buildimage.git
make configure PLATFORM=generic
make target/docker-sonic-mgmt.gz
```

Pre-built *sonic-mgmt* can also be downloaded from [here](https://sonic-jenkins.westus2.cloudapp.azure.com/job/common/job/docker-sonic-mgmt/lastSuccessfulBuild/artifact/target/docker-sonic-mgmt.gz).

- Run *sonic-mgmt* docker
```
docker load -i target/docker-sonic-mgmt.gz
docker run -it docker-sonic-mgmt bash
cd ~/sonic-mgmt
```

From now on, all steps are running inside the *sonic-mgmt* docker.

## Prepare testbed configurations

Latest *sonic-mgmt* repo is cloned into *sonic-mgmt* docker under '/var/[your-login-username]/sonic-mgmt`. 
Once you are in the docker, you need to modify the testbed configuration files to reflect your lab setup.

- Server
  - Update server management IP in [```ansible/veos```](../veos).
  - Update testbed server credentials in [```ansible/group_vars/vm_host/creds.yml```](../group_vars/vm_host/creds.yml).
  - Update server network configuration for VM and PTF management interface in [```ansible/host_vars/STR-ACS-SERV-01.yml```](../host_vars/STR-ACS-SERV-01.yml).
    - ```external_iface```: server trunk port name (connected to the fanout switch)
    - ```mgmt_gw```: ip of gateway for VM mgmt interfaces
    - ```mgmt_prefixlen```: prefixlen for management interfaces
  - Check that ansible could reach this device by command ```ansible -m ping -i veos vm_host_1```.

- VM
  - Download vEOS image from [arista](https://www.arista.com/en/support/software-download).
  - Copy below image files to ```~/veos-vm/images``` on your testbed server.
     - ```Aboot-veos-serial-8.0.0.iso```
     - ```vEOS-lab-4.15.9M.vmdk```
  - Update VM IP addresses [```ansible/veos```](../voes) inventory file. These IP addresses should be in the management subnet defined above.
  - Update VM credentials in [```ansible/group_vars/eos/creds.yml```](../group_vars/eos/creds.yml).

- ```PTF``` docker
  - Update docker registry information in [```vars/docker_registry.yml```](../vars/docker_registry.yml).

## Setup VMs in the server

```
./testbed-cli.sh start-vms server_1 password.txt
```
  - please note: Here "password.txt" is the ansible vault password file name/path. Ansible allows user use ansible vault to encrypt password files. By default, this shell script require a password file. If you are not using ansible vault, just create an empty file and pass the filename to the command line. The file name and location is created and maintained by user. 

Check that all VMs are up and running: ```ansible -m ping -i veos server_1```

## Deploy fanout switch Vlan 
 
You need to specify all lab physical connections before running fanout deployment and some of the tests.  
 
Please follow [Configuration](README.testbed.Config.md) 'Testbed Physical Topology' section to prepare your lab connection graph file.  

We are using Arista switches as fanout switch in our lab. So, the playbook under roles/fanout is for deploy fanout(leaf) switch Vlans configuration of Arista only. If you are using other type of fanout switches, you may manually configure Vlan configurations in switch or you have a good way to deploy regular Layer2 switch configuration in lab would also work. Our fanout switch deploy using Arista switch eosadmin shell login. If you do have an Arista switch as fanout and you want to run the fanout/tasks/main.yml to deploy the switch, please scp the roles/fanout/template/rc.eos file to Arista switch flash, and make sure that you can use your fanout_admin_user/fanout_admin_password to login to shell.  
 
TODO: Improve testbed rootfanout switch configuration method; along we are changing the inventory file format, some of the early fanout definition files has duplicated fields with inventory file, should adopt new inventory file and improve the lab graph 

## Deploy topology

- Update ```testbed.csv``` with your data. At least update PTF mgmt interface settings
- To deploy PTF topology run: ```./testbed-cli.sh add-topo ptf1-m ~/.password```
- To remove PTF topology run: ```./testbed-cli.sh remove-topo ptf1-m ~/.password```
- To deploy T1 topology run: ```./testbed-cli.sh add-topo vms-t1 ~/.password```
- The last step in testbed-cli is trying to re-deploy Vlan range in root fanout switch to match the VLAN range specified in that topology. It's trying to change the 'allowed' Vlan for Arista switch port. If you have other type of switch, it may or may not work. Please review it and change accordingly if required. If you comment out the last step, you may manually swap Vlan ranges in rootfanout to make the testbed topology switch to work.
