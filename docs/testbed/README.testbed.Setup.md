# Testbed Setup

This document describes the steps to setup the testbed and deploy a topology.

## Prepare Testbed Server

- Install Ubuntu 20.04 amd64 on the server. (ubuntu-20.04.1-live-server-amd64.iso)
- Install Ubuntu prerequisites
    ```
    sudo apt -y update
    sudo apt -y upgrade
    sudo apt -y install \
      python3 \
      python-is-python3 \
      python3-pip \
      curl \
      git \
      openssh-server \
      make
    ```
- Install Python prerequisites
    ```
    sudo pip3 install j2cli
    ```
- Install Docker (all credits to https://docs.docker.com/engine/install/ubuntu/ )
    ```
    sudo apt-get remove docker docker-engine docker.io containerd runc
    sudo apt-get update
    sudo apt-get install \
      apt-transport-https \
      ca-certificates \
      curl \
      gnupg-agent \
      software-properties-common
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo apt-key fingerprint 0EBFCD88
    sudo add-apt-repository \
      "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) \
      stable"
    sudo apt-get update
    sudo apt-get install docker-ce docker-ce-cli containerd.io
    sudo docker run hello-world
    ```
    - add your user to docker group
        ```
        sudo usermod -aG docker $USER
        ```
 - enable root (optional)
    ```
    sudo apt -y mc
    /etc/ssh/sshd_config PermitRootLogin yes
    sudo passwd (YourPaSsWoRd)
    sudo systemctl restart sshd
    ```
 - reboot
    - at minimum terminate ssh connection or log out and log back in
    - this is needed for the permissions to be update, otherwise next step will fail

 - Disable firewall (optional)
   ```
   sudo ufw disable
   ```
## Download an cEOS VM image
We use EOS-based VMs or SONiC VMs to simulate neighboring devices in both virtual and physical testbeds. You can use vEOS or SONiC image as neighbor devices, this method can be found in [vEOS (KVM-based) image](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.VsSetup.md#option-1-veos-kvm-based-image) and [SONiC image](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.VsSetup.md#option-3-use-sonic-image-as-neighboring-devices). But for the physical testbed, we recommend using cEOS for **its less consumption of both memory and interaction with the kernel**. To achieve the use of cEOS as neighbor devices, we need to do serveral steps.
1. Pull debian jessie
    ```
    docker pull debian:jessie
    docker tag debian:latest debian:jessie #if the tag is not shown as jessie
    ```
2. Download and import cEOS image manually
Download the [cEOS image from Arista](https://www.arista.com/en/support/software-download)(select version: cEOS-lab-4.25.10M.tar)
3. Import the cEOS image (it will take several minutes to import, so please be patient!)
    ```
    docker import cEOS-lab-4.25.10M.tar ceosimage:4.25.10M
    ```
After imported successfully, you can check it by 'docker images'
```
$ docker images
REPOSITORY                                     TAG           IMAGE ID       CREATED         SIZE
ceosimage                                      4.25.10M     31433ff0fb9b   50 seconds ago     1.62GB
debian                                         jessie        e7d08cddf791   24 months ago   114MB
debian                                         latest        e7d08cddf791   24 months ago   114MB
```
**Note**: *Please also notice the type of the bit for the image, in the example above, it is a standard 32-bit image. Please import the right image as your needs.*


## Build and Run `docker-ptf`

1. The PTF docker container is used to send and receive data plane packets to the DUT. In 'add-topo' step, you can use the Microsoft docker registry host [`/ansible/vars/docker_registry.yml`](/ansible/vars/docker_registry.yml) to obtain docker-ptf directly (**recommended**).

2. If you are using a **local registry** to save the **docker-ptf**, you should obtain a local `docker-ptf` image first:
   You can **either** build a `docker-ptf` from buildimage repo:
    ```
    git clone --recursive https://github.com/sonic-net/sonic-buildimage.git
    cd sonic-buildimage
    make configure PLATFORM=vs ;#takes about 1 hour or more
    make target/docker-ptf.gz
    ```
   **or** download a pre-built `docker-ptf` image [here](https://sonic-build.azurewebsites.net/api/sonic/artifacts?branchName=master&platform=vs&target=target%2Fdocker-ptf.gz) . Then, load the docker-ptf into the docker images:
    ```
    docker load < docker-ptf.gz
    ```
   **Then**, setup your own [Docker Registry](https://docs.docker.com/registry/) and upload `docker-ptf` to your registry:
    ```
    docker pull registry
    docker run -d -p 5000:5000 --name registry registry:latest
    docker image tag docker-ptf 127.0.0.1:5000/docker-ptf
    docker push 127.0.0.1:5000/docker-ptf
    ```
    Also, if you are using a local registry, in later `Prepare Testbed Configuration` step, you have to update the docker registry information in [`vars/docker_registry.yml`](/ansible/vars/docker_registry.yml).
    ```
    #docker_registry_host: sonicdev-microsoft.azurecr.io:443
    docker_registry_host: 127.0.0.1:5000
    docker_registry_username: root
    docker_registry_password: root
    ```

## Build and Run `docker-sonic-mgmt`

Managing the testbed and running tests requires various dependencies to be installed and configured. We have built a `docker-sonic-mgmt` image that takes care of these dependencies so you can use `ansible-playbook`, `pytest`, and `spytest`.

1.  Build `docker-sonic-mgmt` image from scratch (**not recommended**):
    ```
    git clone --recursive https://github.com/sonic-net/sonic-buildimage.git
    cd sonic-buildimage
    make configure PLATFORM=generic
    make target/docker-sonic-mgmt.gz
    ```

    You can also download a pre-built `docker-sonic-mgmt` image [here](https://sonic-build.azurewebsites.net/api/sonic/artifacts?branchName=master&definitionId=194&artifactName=docker-sonic-mgmt&target=target%2Fdocker-sonic-mgmt.gz) (**recommended**).


2. Clone the `sonic-mgmt` repo into your working directory:
    ```
    git clone https://github.com/sonic-net/sonic-mgmt.git
    ```

3. Setup management port configuration using this sample `/etc/network/interfaces`:
    ```
    # replace ma0 with eno1 or your server management nic
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
    for netplan users
    ```
    network:
      version: 2
      ethernets:
        ma0:
          dhcp4: false
          dhcp6: false
      bridges:
        br1:
          interfaces: [ma0]
          addresses: [10.250.0.245/24]
          gateway4: 10.250.0.1
          mtu: 1500
          nameservers:
            addresses: [10.250.0.1, 10.250.0.2]
          parameters:
            stp: false
            forward-delay: 0
            max-age: 0
          dhcp4: no
          dhcp6: no

    ```
    Since the bridge is assigned a virtual ip address, it is better to have one more management network interface (e.g. ma1) so that you can access your server from your lab.

    alternatively use this script but settings will be lost on reboot

    ```
    sudo -H ./sonic-mgmt/ansible/setup-management-network.sh
    ```
4. Reboot the setup just to be sure the networking is ok

5. Create a `docker-sonic-mgmt` container. Note that you must mount your clone of `sonic-mgmt` inside the container to access the deployment and testing scripts:
    ```
    docker load < docker-sonic-mgmt.gz
    docker run -v $PWD:/var/AzDevOps -it docker-sonic-mgmt bash
    cd /var/AzDevOps/sonic-mgmt
    ```

**NOTE: From this point on, all steps are ran inside the `docker-sonic-mgmt` container.**

## Prepare Testbed Configuration

Once you are in the docker container, you need to modify the testbed configuration files to reflect your lab setup.

- Server
    - Update the server management IP in [`ansible/veos`](/ansible/veos).

    - Update the testbed server credentials in [`ansible/group_vars/vm_host/creds.yml`](/ansible/group_vars/vm_host/creds.yml).

    - Update the server network configuration for the VM and PTF management interfaces in [`ansible/host_vars/STR-ACS-SERV-01.yml`](/ansible/host_vars/STR-ACS-SERV-01.yml).
        - `external_port`: server trunk port name (connected to the fanout switch)
        - `mgmt_gw`: ip of the gateway for the VM management interfaces
        - `mgmt_prefixlen`: prefixlen for the management interfaces

    - Check that ansible can reach this host:
        ```
        ansible -m ping -i veos vm_host_1
        ```
    - (Optional) The connectivity to the public internet is necessary during the setup, if the lab env of your organization requires http/https proxy server to reach out to the internet, you need to configure to use the proxy server. It will automatically be leveraged on required steps (e.g. Docker daemon config for image pulling, APT configuration for installing packages). You can configure it in [`ansible/group_vars/all/env.yml`](https://github.com/sonic-net/sonic-mgmt/blob/master/ansible/group_vars/all/env.yml)

- VMs
    - Update /ansible/group_vars/vm_host/main.yml with the location of the veos files or veos file name if you downloaded a different version
    - Update the VM IP addresses in the [`ansible/veos`](/ansible/veos) inventory file. These IP addresses should be in the management subnet defined above.

    - Update the VM credentials in `ansible/group_vars/eos/creds.yml`.
    ```
    cat <<EOT >> /data/sonic-mgmt/ansible/group_vars/eos/creds.yml
    ---
    ansible_password: '123456'
    ansible_user: admin
    EOT
    ```
    -update the cEOS vars in [`ansible/group_vars/all/ceos.ymal`](/ansible/group_vars/all/ceos.yml).
    ```
    ceos_image_filename: cEOS64-lab-4.25.10M.tar
    ceos_image_orig: ceosimage:4.25.10M
    ceos_image: ceosimage:4.25.10M
    skip_ceos_image_downloading: true
    ```
    **NOTE**: We are using local ceos image, hence the skip ceos image downloading should be set as true.


## Deploy physical Fanout Switch VLAN

You need to specify all physical connections that exist in the lab before deploying the fanout and running the tests.

Please follow the "Testbed Physical Topology" section of the [Configuration Guide](README.testbed.Config.md) to prepare your lab connection graph file.

We are using Arista switches as the fanout switches in our lab. So, the playbook under `roles/fanout` is for deploying fanout (leaf) switch Vlan configurations on Arista devices only. If you are using other types of fanout switches, you can manually configure the Vlan configurations on the switch, or you can deploy a regular Layer-2 switch configuration.

Our fanout switches deploy using the Arista switch's eosadmin shell login. If you have an Arista switch as your fanout and you want to run `fanout/tasks/main.yml` to deploy the switch, please `scp` the `roles/fanout/template/rc.eos` file to the Arista switch flash, and make sure that you can login to the shell with `fanout_admin_user/fanout_admin_password`.

**`TODO:`**
- Improve testbed root fanout switch configuration method.
- Update the inventory file format. Some of the early fanout definition files have duplicated fields with the inventory file. We should adopt a new inventory file and improve the lab graph.


## Setup VMs and add topology on the Server
For we are using cEOS now, the start-vms step is combined into add topo step.
- Update `testbed.csv` with your data. At the least, you should update the PTF management interface settings.
- To deploy a topology run: ```./testbed-cli.sh -m veos -k ceos add-topo vms-t0 password.txt```
- To remove a topology run: ```./testbed-cli.sh -m veos -k ceos remove-topo vms-t0 password.txt```

**NOTE:** The last step in `testbed-cli.sh` is trying to re-deploy the Vlan range in the root fanout switch to match the VLAN range specified in the topology. In other words, it's trying to change the "allowed" Vlan for the Arista switch ports. If you have a different type of switch, this may or may not work. Please review the steps and update accordingly if necessary. If you comment out the last step, you may manually swap Vlan ranges in the root fanout to make the testbed topology switch work.

When ```add-topo``` step finished, you can check the cEOS on your server (outside the docker-sonic-mgmt)
```
CONTAINER ID   IMAGE                                 COMMAND                  CREATED         STATUS        PORTS                                       NAMES
d3c0609b6072   ceosimage:4.25.10M                 "/sbin/init systemd.…"   30 hours ago    Up 30 hours                                               ceos_vms1-1_VM0103
44e00555ef1f   ceosimage:4.25.10M                 "/sbin/init systemd.…"   30 hours ago    Up 30 hours                                               ceos_vms1-1_VM0102
290769ffee8a   ceosimage:4.25.10M                 "/sbin/init systemd.…"   30 hours ago    Up 30 hours                                               ceos_vms1-1_VM0101
fcffb9e0106e   ceosimage:4.25.10M                 "/sbin/init systemd.…"   30 hours ago    Up 30 hours                                               ceos_vms1-1_VM0100
8e8f8d9aff8a   debian:jessie                         "bash"                   30 hours ago    Up 30 hours                                               net_vms1-1_VM0103
835ae77bc3cd   debian:jessie                         "bash"                   30 hours ago    Up 30 hours                                               net_vms1-1_VM0102
afdcd58f7d88   debian:jessie                         "bash"                   30 hours ago    Up 30 hours                                               net_vms1-1_VM0101
9b29d5e7f083   debian:jessie                         "bash"                   30 hours ago    Up 30 hours                                               net_vms1-1_VM0100
```

You can login to the cEOS
```
docker exec -it ceos_vms1-1_VM0101 Cli
ARISTA02T1>show version
 cEOSLab
Hardware version:
Serial number:
Hardware MAC address: 1673.3c9c.7d68
System MAC address: 1673.3c9c.7d68

Software image version: 4.25.10M-29053933.42510M (engineering build)
Architecture: i686
Internal build version: 4.25.10M-29053933.42510M
Internal build ID: bfec0be6-4a3e-40f1-89e5-446718454c89

cEOS tools version: 1.1
Kernel version: 5.4.0-135-generic

Uptime: 0 weeks, 1 days, 6 hours and 10 minutes
Total memory: 32407156 kB
Free memory: 24488032 kB

```


## Deploy Minigraph

Please follow the "Device Minigraph Generation and Deployment" section of the [Device Minigraph Generation and Deployment](README.testbed.Minigraph.md) to finish minigraph deployment.
