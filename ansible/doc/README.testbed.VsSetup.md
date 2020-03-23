# Testbed Setup

This document describes the steps to setup the virtual switch based testbed and deploy a topology.

## Prepare testbed server

- Install Ubuntu 18.04 amd64 server. To setup a T0 topology, the server needs to have 10GB free memory.
- Install bridge utils
```
$ sudo apt-get install bridge-utils
```
- Setup internal management network.

```
$ sudo brctl addbr br1
$ sudo ifconfig br1 10.250.0.1/24
$ sudo ifconfig br1 up
```

### Use vEOS image

- Download vEOS image from [arista](https://www.arista.com/en/support/software-download).
- Copy below image files to ```~/veos-vm/images``` on your testbed server.
   - ```Aboot-veos-serial-8.0.0.iso```
   - ```vEOS-lab-4.20.15M.vmdk```

### Use cEOS image (experimental)
- Download cEOS image from [arista](https://www.arista.com/en/support/software-download) onto your testbed server
- Import cEOS image

```
$ docker import cEOS64-lab-4.23.2F.tar.xz ceosimage:4.23.2F
$ docker images
REPOSITORY                                     TAG                 IMAGE ID            CREATED             SIZE
ceosimage                                      4.23.2F             d53c28e38448        2 hours ago         1.82GB
```

## Build or download *sonic-mgmt* docker image

ansible playbook in *sonic-mgmt* repo requires to setup ansible and various dependencies.
We have built a *sonic-mgmt* docker that installs all dependencies, and you can build
the docker and run ansible playbook inside the docker.

- Build *sonic-mgmt* docker
```
$ git clone --recursive https://github.com/Azure/sonic-buildimage.git
$ make configure PLATFORM=generic
$ make target/docker-sonic-mgmt.gz
```

- Download pre-built *sonic-mgmt* image from [here](https://sonic-jenkins.westus2.cloudapp.azure.com/job/bldenv/job/docker-sonic-mgmt/lastSuccessfulBuild/artifact/sonic-buildimage/target/docker-sonic-mgmt.gz).
```
$ wget https://sonic-jenkins.westus2.cloudapp.azure.com/job/bldenv/job/docker-sonic-mgmt/lastSuccessfulBuild/artifact/sonic-buildimage/target/docker-sonic-mgmt.gz
```

- Load *sonic-mgmt* image
```
$ docker load -i docker-sonic-mgmt.gz
```

## Download sonic-vs image

- Download sonic-vs image from [here](https://sonic-jenkins.westus2.cloudapp.azure.com/job/vs/job/buildimage-vs-image/lastSuccessfulBuild/artifact/target/sonic-vs.img.gz)
```
$ wget https://sonic-jenkins.westus2.cloudapp.azure.com/job/vs/job/buildimage-vs-image/lastSuccessfulBuild/artifact/target/sonic-vs.img.gz
```

- unzip the image and move it into ```~/sonic-vm/images/```
```
$ gzip -d sonic-vs.img.gz
$ mkdir -p ~/sonic-vm/images
$ mv sonic-vs.img ~/sonic-vm/images
```

## Clone sonic-mgmt repo

```
$ git clone https://github.com/Azure/sonic-mgmt
```

## Run sonic-mgmt docker

(run following command from a place where the newly cloned sonic-mgmt repo is accessible, e.g. home directory or the parent fold of sonic-mgmt, the point is that you want to run following deployment and test commands from this repo)

```
$ docker run -v $PWD:/data -it docker-sonic-mgmt bash
```

From now on, all steps are running inside the *sonic-mgmt* docker.

### Setup public key to login into the linux host from sonic-mgmt docker

- Modify veos.vtb to use the user name, e.g., ```foo``` to login linux host.

```
lgh@gulv-vm2:/data/sonic/sonic-mgmt/ansible$ git diff
diff --git a/ansible/veos.vtb b/ansible/veos.vtb
index 4ea5a7a..4cfc448 100644
--- a/ansible/veos.vtb
+++ b/ansible/veos.vtb
@@ -1,5 +1,5 @@
[vm_host_1]
-STR-ACS-VSERV-01 ansible_host=172.17.0.1 ansible_user=use_own_value
+STR-ACS-VSERV-01 ansible_host=172.17.0.1 ansible_user=foo

 [vm_host:children]
vm_host_1
```

- Add user ```foo```'s public key to ```/home/foo/.ssh/authorized_keys``` on the host

- Add user ```foo```'s private key to ```$HOME/.ssh/id_rsa``` inside sonic-mgmt docker container.

- Test you can login into box using 
```ssh foo@172.17.0.1``` without any password prompt inside the docker container.

## Setup Arista VMs in the server

(skip this step if you use cEOS image)

```
$ ./testbed-cli.sh -m veos.vtb -n 4 start-vms server_1 password.txt
```
  - please note: Here "password.txt" is the ansible vault password file name/path. Ansible allows user use ansible vault to encrypt password files. By default, this shell script require a password file. If you are not using ansible vault, just create an empty file and pass the filename to the command line. The file name and location is created and maintained by user.

Check that all VMs are up and running, and the passwd is ```123456```
```
$ ansible -m ping -i veos.vtb server_1 -u root -k
VM0102 | SUCCESS => {
        "changed": false,
                "ping": "pong"
}
VM0101 | SUCCESS => {
        "changed": false,
                "ping": "pong"
}
STR-ACS-VSERV-01 | SUCCESS => {
        "changed": false,
                "ping": "pong"
}
VM0103 | SUCCESS => {
        "changed": false,
                "ping": "pong"
}
VM0100 | SUCCESS => {
        "changed": false,
                "ping": "pong"
}
```


## Deploy T0 topology

### vEOS
```
$ ./testbed-cli.sh -t vtestbed.csv -m veos.vtb add-topo vms-kvm-t0 password.txt
```

### cEOS
```
$ ./testbed-cli.sh -t vtestbed.csv -m veos.vtb -k ceos add-topo vms-kvm-t0 password.txt
```

Verify topology setup successfully.

```
$ docker ps
CONTAINER ID        IMAGE                                                 COMMAND                  CREATED              STATUS              PORTS               NAMES
575064498cbc        ceosimage:4.23.2F                                     "/sbin/init systemd.…"   About a minute ago   Up About a minute                       ceos_vms6-1_VM0103
d71b8970bcbb        debian:jessie                                         "bash"                   About a minute ago   Up About a minute                       net_vms6-1_VM0103
3d2e5ecdd472        ceosimage:4.23.2F                                     "/sbin/init systemd.…"   About a minute ago   Up About a minute                       ceos_vms6-1_VM0102
28d64c74fa54        debian:jessie                                         "bash"                   About a minute ago   Up About a minute                       net_vms6-1_VM0102
0fa067a47c7f        ceosimage:4.23.2F                                     "/sbin/init systemd.…"   About a minute ago   Up About a minute                       ceos_vms6-1_VM0101
47066451fa4c        debian:jessie                                         "bash"                   About a minute ago   Up About a minute                       net_vms6-1_VM0101
e07bd0245bd9        ceosimage:4.23.2F                                     "/sbin/init systemd.…"   About a minute ago   Up About a minute                       ceos_vms6-1_VM0100
4584820bf368        debian:jessie                                         "bash"                   7 minutes ago        Up 7 minutes                            net_vms6-1_VM0100
c929c622232a        sonicdev-microsoft.azurecr.io:443/docker-ptf:latest   "/usr/local/bin/supe…"   7 minutes ago        Up 7 minutes                            ptf_vms6-1
```

## Deploy minigraph on the DUT

```
$ ./testbed-cli.sh -t vtestbed.csv -m veos.vtb deploy-mg vms-kvm-t0 lab password.txt
```

You should be login into the sonic kvm using IP: 10.250.0.101 using admin:password.
You should see BGP sessions up in sonic.

```
admin@vlab-01:~$ show ip bgp sum
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
