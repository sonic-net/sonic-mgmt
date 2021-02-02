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
    - at minimum terminate ssh conection or log out and log back in 
    - this is needed for the permisions to be update, otherwise next step will fail

## Setup Docker Registry for `docker-ptf`

The PTF docker container is used to send and receive data plane packets to the DUT.

1. Build `docker-ptf` image
    ```
    git clone --recursive https://github.com/Azure/sonic-buildimage.git
    cd sonic-buildimage
    make configure PLATFORM=vs ;#takes about 1 hour or more
    make target/docker-ptf.gz
    ```

2. Setup your own [Docker Registry](https://docs.docker.com/registry/) and upload `docker-ptf` to your registry.

## Build and Run `docker-sonic-mgmt`

Managing the testbed and running tests requires various dependencies to be installed and configured. We have built a `docker-sonic-mgmt` image that takes care of these dependencies so you can use `ansible-playbook`, `pytest`, and `spytest`.

1.  Build `docker-sonic-mgmt` image from scratch:
    ```
    git clone --recursive https://github.com/Azure/sonic-buildimage.git
    cd sonic-buildimage
    make configure PLATFORM=generic
    make target/docker-sonic-mgmt.gz
    ```

    You can also download a pre-built `docker-sonic-mgmt` image [here](https://sonic-jenkins.westus2.cloudapp.azure.com/job/bldenv/job/docker-sonic-mgmt/lastSuccessfulBuild/artifact/sonic-buildimage/target/docker-sonic-mgmt.gz).

2. Clone the `sonic-mgmt` repo into your working directory:
    ```
    git clone https://github.com/Azure/sonic-mgmt
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
    alternativeley use this script but settings will be lost on reboot

    ```
    sudo bash ./sonic-mgmt/ansible/setup-management-network.sh
    ```
4. Reboot the setup just to be sure the networking is ok

5. Create a `docker-sonic-mgmt` container. Note that you must mount your clone of `sonic-mgmt` inside the container to access the deployment and testing scripts:
    ```
    docker load < docker-sonic-mgmt.gz
    docker load < docker-ptf.gz
    docker run -v $PWD:/data -it docker-sonic-mgmt bash
    cd /data/sonic-mgmt
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

- VMs
    - Download [vEOS-lab image from Arista](https://www.arista.com/en/support/software-download).

    - Copy these image files to `~/veos-vm/images` on your testbed server:
        - `Aboot-veos-serial-8.0.0.iso`
        - `vEOS-lab-4.20.15M.vmdk`

    - Update /ansible/group_vars/vm_host/main.yml with the location of the veos files or veos file name if you downloaded a diferent version
    - Update the VM IP addresses in the [`ansible/veos`](/ansible/veos) inventory file. These IP addresses should be in the management subnet defined above.

    - Update the VM credentials in `ansible/group_vars/eos/creds.yml`.
    ```
    cat <<EOT >> /data/sonic-mgmt/ansible/group_vars/eos/creds.yml
    ---
    ansible_password: '123456'
    ansible_user: admin
    EOT
    ```

- PTF Docker
    - Update the docker registry information in [`vars/docker_registry.yml`](/ansible/vars/docker_registry.yml).

## Setup VMs on the Server

1. Start the VMs:
    ```
    # /data/sonic-mgmt/ansible
    ./testbed-cli.sh start-vms server_1 password.txt
    ```
    Please note: `password.txt` is the ansible vault password file name/path. Ansible allows users to use `ansible-vault` to encrypt password files. By default, this shell script **requires** a password file. If you are not using `ansible-vault`, just create an empty file and pass the file name to the command line. **The file name and location is created and maintained by the user.**
    ```
    echo "" > ./password.txt
    ```

2. Check that all the VMs are up and running:
    ```
    ansible -m ping -i veos server_1
    ```

## Deploy Fanout Switch VLAN

You need to specify all physical connections that exist in the lab before deploying the fanout and running the tests.

Please follow the "Testbed Physical Topology" section of the [Configuration Guide](README.testbed.Config.md) to prepare your lab connection graph file.

We are using Arista switches as the fanout switches in our lab. So, the playbook under `roles/fanout` is for deploying fanout (leaf) switch Vlan configurations on Arista devices only. If you are using other types of fanout switches, you can manually configure the Vlan configurations on the switch, or you can deploy a regular Layer-2 switch configuration.

Our fanout switches deploy using the Arista switch's eosadmin shell login. If you have an Arista switch as your fanout and you want to run `fanout/tasks/main.yml` to deploy the switch, please `scp` the `roles/fanout/template/rc.eos` file to the Arista switch flash, and make sure that you can login to the shell with `fanout_admin_user/fanout_admin_password`.

**`TODO:`**
- Improve testbed root fanout switch configuration method.
- Update the inventory file format. Some of the early fanout definition files have duplicated fields with the inventory file. We should adopt a new inventory file and improve the lab graph.

## Deploy Topology

- Update `testbed.csv` with your data. At the least, you should update the PTF management interface settings.
- To deploy a topology run: ```./testbed-cli.sh add-topo vms-t1 ~/.password```
- To remove a topology run: ```./testbed-cli.sh remove-topo vms-t1 ~/.password```

**NOTE:** The last step in `testbed-cli.sh` is trying to re-deploy the Vlan range in the root fanout switch to match the VLAN range specified in the topology. In other words, it's trying to change the "allowed" Vlan for the Arista switch ports. If you have a different type of switch, this may or may not work. Please review the steps and update accordingly if necessary. If you comment out the last step, you may manually swap Vlan ranges in the root fanout to make the testbed topology switch work.
