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

- Download vEOS image from [arista](https://www.arista.com/en/support/software-download).
- Copy below image files to ```~/veos-vm/images``` on your testbed server.
   - ```Aboot-veos-serial-8.0.0.iso```
   - ```vEOS-lab-4.15.9M.vmdk```

## Setup docker registry for *PTF* docker

PTF docker is used to send and receive packets to test data plane. 

- Build PTF docker
```
$ git clone --recursive https://github.com/Azure/sonic-buildimage.git
$ make configure PLATFORM=generic
$ make target/docker-ptf.gz
```

- Download pre-built *docker-ptf* image from [here](https://sonic-jenkins.westus2.cloudapp.azure.com/job/broadcom/job/buildimage-brcm-all/lastSuccessfulBuild/artifact/target/docker-ptf-brcm.gz)
```
$ wget https://sonic-jenkins.westus2.cloudapp.azure.com/job/broadcom/job/buildimage-brcm-all/lastSuccessfulBuild/artifact/target/docker-ptf-brcm.gz
```

- Load *docker-ptf* image
```
$ docker load -i docker-ptf-brcm.gz
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

- Download pre-built *sonic-mgmt* image from [here](https://sonic-jenkins.westus2.cloudapp.azure.com/job/bldenv/job/docker-sonic-mgmt/lastSuccessfulBuild/artifact/target/docker-sonic-mgmt.gz).
```
$ wget https://sonic-jenkins.westus2.cloudapp.azure.com/job/bldenv/job/docker-sonic-mgmt/lastSuccessfulBuild/artifact/target/docker-sonic-mgmt.gz
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

### Modify login user name
```
lgh@gulv-vm2:/data/sonic/sonic-mgmt/ansible$ git diff
diff --git a/ansible/veos.vtb b/ansible/veos.vtb
index 4ea5a7a..4cfc448 100644
--- a/ansible/veos.vtb
+++ b/ansible/veos.vtb
@@ -1,5 +1,5 @@
[vm_host_1]
-STR-ACS-VSERV-01 ansible_host=172.17.0.1 ansible_user=use_own_value
+STR-ACS-VSERV-01 ansible_host=172.17.0.1 ansible_user=lgh

 [vm_host:children]
vm_host_1
```

## Run sonic-mgmt docker

```
$ docker run -v $PWD:/data -it docker-sonic-mgmt bash
```

From now on, all steps are running inside the *sonic-mgmt* docker.

### Setup public key to login into the linux host from sonic-mgmt docker

- Modify veos.vtb to use the user name to login linux host. Add public key to authorized\_keys for your user. 
Put the private key inside the sonic-mgmt docker container. Make sure you can login into box using 
```ssh yourusername@172.17.0.1``` without any password prompt inside the docker container.

## Setup Arista VMs in the server

```
$ ./testbed-cli.sh -m veos.vtb start-vms server_1 password.txt
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

```
$ ./testbed-cli.sh -t vtestbed.csv -m veos.vtb add-topo vms-kvm-t0 password.txt
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
