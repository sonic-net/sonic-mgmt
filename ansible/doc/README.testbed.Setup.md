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
- Add Docker’s official GPG key
```
   $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
```

## Build and run ```sonic-mgmt``` docker

ansible playbook in ```sonic-mgmt``` repo requires to setup ansible and various dependencies.
We have built a ```sonic-mgmt``` docker that installs all dependencies, and you can simply
build that docker and ansible playbook inside the docker.

- Build ```sonic-mgmt``` docker
```
git clone --recursive https://github.com/Azure/sonic-buildimage.git
make target/docker-sonic-mgmt.gz
```

- Run ```sonic-mgmt``` docker
```
docker load -i target/docker-sonic-mgmt.gz
docker run -it docker-sonic-mgmt bash
cd ~/sonic-mgmt
```

From now on, all steps are running inside the ```sonic-mgmt``` docker.

## Prepare testbed configurations

Prepare various configuration files for your testbed.

- Add/Update your testbed server management IP in veos file. Example:'STR-ACS-SERV-01 ansible_host=10.0.0.5' where 10.0.0.5 your server mgmt ip
- Add testbed server credentials in ```ansible/group_vars/vm_host/creds.yml```
- Check that ansible could reach this device by command ```ansible -m ping -i veos vm_host_1```
- Put files: ```Aboot-veos-serial-8.0.0.iso``` and ```vEOS-lab-4.15.9M.vmdk``` to /home/{your_username from step 3}/veos-vm/images on your testbed server
- Edit ```ansible/host_vars/STR-ACS-SERV-01.yml```. You need to change ```external_iface```,```mgmt_gw``` and ```mgmt_prefixlen```. These settings define network parameters for VM/ptf management interfaces. Example:

```
external_iface: p4p1   <--- trunk port of the server (connected to the fanout switch)
mgmt_gw: 10.250.0.1    <--- ip of gateway for VM mgmt interfaces
mgmt_prefixlen: 24     <--- prefixlen for management interfaces
```

- Add ip addresses for your VMs in veos inventory file ```ansible/veos``` inventory file. These IP addresses should be in the management subnet defined in above file.
- Update VM credentials in ```ansible/group_vars/eos/creds.yml```. Use root:123456 as credentials
- Add information about your docker registry here: ```vars/docker_registry.yml```

## Setup VMs in the server


```
./testbed-cli.sh start-vms server_1 password.txt
```

Check that all VMs are up and running: ```ansible -m ping -i veos server_1```

## Deploy topology

- Update testbed.csv with your data. At least update PTF mgmt interface settings
- To deploy PTF topology run: ```./testbed-cli.sh add-topo ptf1-m ~/.password```
- To remove PTF topology run: ```./testbed-cli.sh remove-topo ptf1-m ~/.password```
- To deploy T1 topology run: ```./testbed-cli.sh add-topo vms-t1 ~/.password```
