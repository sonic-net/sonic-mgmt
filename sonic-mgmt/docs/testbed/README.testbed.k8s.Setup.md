# SONiC Kubernetes Design

This document describes the testbed design for Kubernetes features in SONiC and provides instructions to set up the high availability Kubernetes master.

## Background

Each SONiC DUT is a worker node managed by a High Availability Kubernetes master. The High Availability Kubernetes master is composed of three master node machines and one load balancer machine.

By connecting each SONiC DUT to HA Kubernetes master, containers running in SONiC can be managed by the Kubernetes master. SONiC containers managed by the Kubernetes master are termed to be running in "kube mode" as opposed to the original "local mode."

In local mode, the SONiC feature container runs based on the image tagged `feature_name:latest` in the local image store; this feature runs independent of the Kubernetes master. In kube mode, SONiC container properties are based on specifications defined in the associated Kubernetes manifest. A Kubernetes manifest is a file in the Kubernetes master that defines the Kubernetes object and container configurations, including a URL from which to source the feature image. In our case, we use Kubernetes Daemonset objects. The Kubernetes Daemonset object ensures that each worker node is running exactly one container of the image specified in the Daemonset manifest file.

For example, in order to run SNMP and Telemetry containers in kube mode, we must have two manifests that define two Kubernetes Daemonset objects- one for each container/feature running in kube mode.

The following is a snippet of the Telemetry Daemonset manifest file that specifies the Kubernetes object type and container image:

```
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: telemetry-ds
spec:
  template:
    metadata:
      labels:
        name: telemetry
    spec:
      hostname: sonic
      hostNetwork: true
      containers:
      - name: telemetry
        image: sonicanalytics.azurecr.io/sonic-dockers/any/docker-sonic-telemetry:20200531
        tty: true
            .
            .
            .
```


## Topology Overview

In order to connect each physical SONiC DUT to a High Availability Kubernetes master, we need to set up the following topology:
![alt text](https://github.com/isabelmsft/k8s-ha-master-starlab/blob/master/k8s-testbed-linux.png)
- Each high availability master setup requires 4 new Linux KVMs running on a Testbed Server via bridged networking.
    - 3 Linux KVMs to serve as 3-node high availability Kubernetes master
    - 1 Linux KVM to serve as HAProxy Load Balancer node
- Each KVM has one management interface assigned an IP address reachable from SONiC DUT.
- HAProxy Load Balancer proxies requests to 3 backend Kubernetes master nodes.

In the case of a virtual SONiC DUT, the SONiC KVM and 4 new Linux KVMs for the Kubernetes master are all running on the Testbed Server (or host VM). Each KVM is connected to an internal management network, Linux bridge br1. Internal management network setup for the virtual DUT is described in [How to Setup High Availability Kubernetes Master for Virtual DUT](#how-to-setup-high-availability-kubernetes-master-for-virtual-dut) below.

Our setup meets Kubernetes Minimum Requirements to setup a High Availability cluster. The Minimum Requirements are as follows:
- 2 GB or more of RAM per machine
- 2 CPUs or more per machine
- Full network connectivity between all machines in the cluster (public or private network)
- sudo privileges on all machines
- SSH access from one device to all nodes in the system

## How to Setup High Availability Kubernetes Master for Physical DUT

#### To create a HA Kubernetes master for Physical DUT:
1. Prepare Testbed Server and build and run `docker-sonic-mgmt` container as described [here](README.testbed.Setup.md)
2. Allocate 4 available IPs reachable from SONiC DUT.
3. Update [`ansible/k8s_ubuntu`](/ansible/k8s_ubuntu) to include your 4 newly allocated IP addresses for the HA Kubernetes master and IP address of testbed server.

  - We will walk through an example of setting up HA Kubernetes master set 1 on server 19 (STR-ACS-SERV-19). The following snippets are the relevant portions from [`ansible/k8s_ubuntu`](/ansible/k8s_ubuntu).

   ```
   k8s_vm_host19:
     hosts:
       STR-ACS-SERV-19:
         ansible_host: 10.251.0.101
  ```
  - Replace `ansible_host` value above with the IP address of the testbed server.

  ```
  k8s_vms1_19:
  hosts:
    kvm19-1m1:
      ansible_host: 10.250.0.2
      master: true
      master_leader: true
    kvm19-1m2:
      ansible_host: 10.250.0.3
      master: true
      master_member: true
    kvm19-1m3:
      ansible_host: 10.250.0.4
      master_member: true
      master: true
    kvm19-1ha:
      ansible_host: 10.250.0.5
      haproxy: true
  ```

  - Replace each `ansible_host` value with an IP address allocated in step 2.

  - Take note of the group name `k8s_vms1_19`. At the top of [`ansible/k8s_ubuntu`](/ansible/k8s_ubuntu), make sure that `k8s_server_19` has its `host_var_file` and two `children` properly set:

```
k8s_server_19:
  vars:
    host_var_file: host_vars/STR-ACS-SERV-19.yml
  children:
    k8s_vm_host19:
    k8s_vms1_19:
```

4. Update the server network configuration for the Kubernetes VM management interfaces in [`ansible/host_vars/STR-ACS-SERV-19.yml`](/ansible/host_vars/STR-ACS-SERV-19.yml).
    - `mgmt_gw`: ip of the gateway for the VM management interfaces
    - `mgmt_prefixlen`: prefixlen for the management interfaces
5. If necessary, set proxy in [`ansible/group_vars/all/env.yml`](/ansible/group_vars/all/env.yml).
6. If necessary, specify DNS server IP in [`ansible/host_vars/STR-ACS-SERV-19.yml`](/ansible/host_vars/STR-ACS-SERV-19.yml). This should be the same DNS server IP as used by the host machine. If proxy server is configured and takes care of DNS, this step is not necessary.
7. Update the testbed server credentials in [`ansible/group_vars/k8s_vm_host/creds.yml`](/ansible/group_vars/k8s_vm_host/creds.yml). Also, set your own Kubernetes master Ubuntu KVM password in [`ansible/group_vars/all/creds.yml`](/ansible/group_vars/all/creds.yml).
8. If using Azure Storage to source Ubuntu 18.04 KVM image, set `k8s_vmimage_saskey` in [`ansible/vars/azure_storage.yml`](/ansible/vars/azure_storage.yml).
   - To source image from public URL: download from  [here](https://cloud-images.ubuntu.com/bionic/current/bionic-server-cloudimg-amd64.img). Then, convert img to qcow2 by running `qemu-img convert -f qcow2 bionic-server-cloudimg-amd64.img bionic-server-cloudimg-amd64.qcow2`. Store qcow2 image at the path `/home/azure/ubuntu-vm/images/bionic-server-cloudimg-amd64.qcow2` on your testbed server.
9. From `docker-sonic-mgmt` container, `cd` into `sonic-mgmt/ansible` directory and run `./testbed-cli.sh -m k8s_ubuntu [additional OPTIONS] create-master <k8s-server-name> ~/.password`
   - `k8s-server-name` corresponds to the group name used to describe the testbed server in the [`ansible/k8s_ubuntu`](/ansible/k8s_ubuntu) inventory file, of the form `k8s_server_{unit}`.
   - Please note: `~/.password` is the ansible vault password file name/path. Ansible allows users to use ansible-vault to encrypt password files. By default, this shell script requires a password file. If you are not using ansible-vault, just create an empty file and pass the file name to the command line. The file name and location are created and maintained by the user.
   - For HA Kubernetes master set 1 running on server 19 shown above, the proper command would be:
`./testbed-cli.sh -m k8s_ubuntu create-master k8s_server_19 ~/.password`
  - OPTIONAL: We offer the functionality to run multiple master sets on one server.
    - Each master set is one HA Kubernetes master composed of 4 Linux KVMs.
    - Should an additional HA master set be necessary on an occupied server, add the option `-s <msetnumber>`, where `msetnumber` would be 2 if this is the 2nd master set running on `<k8s-server-name>`. Make sure that [`ansible/k8s-ubuntu`](/ansible/k8s-ubuntu) is updated accordingly. Specifically, make sure that the IPS are set in the correct group `k8s_vms{msetnumber}_{servernumber}` and the `children` are properly updated for `k8s_server_{servernumber}` at the bottom of the inventory file. `msetnumber` is 1 by default.
10. Join Kubernetes-enabled SONiC DUT to master by configuring VIP and enabling the Kubernetes server/master connection. Kubernetes server is enabled by default
    - `sudo config kube server ip <VIP>`
    - `sudo config kube server disable off` (default configuration)


#### To remove a HA Kubernetes master for Physical DUT:
- Run `./testbed-cli.sh -m k8s_ubuntu [additional OPTIONS] destroy-master <k8s-server-name> ~/.password`
- For HA Kubernetes master set 1 running on server 19 shown above, the proper command would be:
`./testbed-cli.sh -m k8s_ubuntu destroy-master k8s_server_19 ~/.password`

## How to Setup High Availability Kubernetes Master for Virtual DUT

#### To create a HA Kubernetes master for Virtual DUT:
1. Setup internal management network:
```
$ git clone https://github.com/Azure/sonic-mgmt
$ cd sonic-mgmt/ansible
$ sudo ./setup-management-network.sh
$ sudo ./setup-br1-nat.sh <name of server's external facing port>
```
2. Setup virtual switch testbed as described [here](README.testbed.VsSetup.md). **Note:** if the host machine is a VM, nested virtualization must be enabled.
3. In [`ansible/k8s_ubuntu_vtb`](/ansible/k8s_ubuntu_vtb), replace `use_own_value` with the username for the server, corresponds to the username used while setting up [`ansible/veos_vtb`](/ansible/veos_vtb) for the virtual switch testbed.
4. If necessary, set proxy in [`ansible/group_vars/all/env.yml`](/ansible/group_vars/all/env.yml).
5. If necessary, specify DNS server IP to be used by Ubuntu KVMs in [`ansible/host_vars/STR-ACS-VSERV-21.yml`](/ansible/host_vars/STR-ACS-VSERV-21.yml); this should be the same DNS server IP as used by the host machine. If proxy server is configured and takes care of DNS, this step is not necessary.
6. From inside the `sonic-mgmt` docker set up in step 2, run:
```
$ cd /data/sonic-mgmt/ansible
$ ./testbed-cli.sh -m k8s_ubuntu_vtb create-master k8s_server_21 password.txt
```
#### To remove a HA Kubernetes master for Virtual DUT:
```
$ cd /data/sonic-mgmt/ansible
$ ./testbed-cli.sh -m k8s_ubuntu_vtb destroy-master k8s_server_21 password.txt
```

## Testing Scope

This setup allows us to test the following:
- Joining and removing/resetting of SONiC DUT from Kubernetes master
- Upgrades of kube mode feature images via Kubernetes manifests
- SONiC feature transition between kube mode and local mode
- Proper management of kube mode features before and after SONiC reboots

During each of the following states:
- When master VIP is reachable
- When master VIP is unrechable
- When Kubernetes API server is available
- When Kubernetes API server unavailable

In this setup, we do not consider load balancer performance. For Kubernetes feature testing purposes, HAProxy is configured to perform vanilla round-robin load balancing on available master servers.
