# OCS TestBed Setup
This document describes the steps to setup an optical circuit switch(OCS) testbed, delpoy OCS to the sonic-mgmt test framework for scripts running.

## Prepare Testbed host
According to testbed.Setup[testbed.Setup], prepare a PC with Ubuntu 20.04(recommanded), install the necessary libraries, and download sonic-mgmt docker container for test scripts running as well as a PTF container for service distribution.

1. Install Ubuntu AMD64 on your host or VM
    - The host PC needs to have at least 20GB of memory free
    - If the testbed host is a VM, then it must support nested virtualization
        - [Instructions for Hyper-V based VMs](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization#configure-nested-virtualization)
2. Prepare your environment based on Ubuntu
    The Ubuntu version now is recommanded with **Ubuntu 20.04**
    ```
    sudo apt install python3 python3-pip openssh-server
    ```
    If checked the default python version with command `python --version`, the python version on server now is still 2.x. After install python3, replace python command with python3 using symbolic link:
    ```
    sudo ln -sf /usr/bin/python3 /usr/bin/python
    ```

    For more Ubuntu version, running this testbed needs to be explored for compatibility.
3. Download the latest version of sonic-mgmt on github
   Create a folder to store the cloned files of sonic-mgmt test scripts.   
    ```
    cd ~
    mkdir SONiC
    chmod 777 SONiC
    git clone https://github.com/sonic-net/sonic-mgmt
    ```
    Check download script in folder:
    ```
    /SONiC# ls
    sonic-mgmt
    /SONiC/sonic-mgmt# ls
    ansible  azure-pipelines.yml  docs  LICENSE  pylintrc  pyproject.toml  README.md  sdn_tests  SECURITY.md  setup-container.sh  sonic_dictionary.txt  spytest  test_reporting  tests
    ```
4. [Install Docker CE](https://docs.docker.com/install/linux/docker-ce/ubuntu/). Be sure to follow the [post-install instructions](https://docs.docker.com/install/linux/linux-postinstall/) so that you don't need sudo privileges to run docker commands.

## Download sonic-mgmt docker container
1. The simplest way way to run the script on testbed is to deploy the official Docker and run cases within the Docker, so there is no need to deploy the required runtime libraries separately.
   - Build the test enviroment on sonic-vs container. 
    ```
    docker pull sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest
    ```
2. Check if the Docker image has been installed on host.
    ```
    docker images
    REPOSITORY                                            TAG       IMAGE ID       CREATED        SIZE
    sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt   latest    0550f2d12fde   2 months ago   3.43GB
    ```
## Setup sonic-mgmt docker
All testbed configurations and test procedures execute within a sonic-mgmt Docker container, providing a standardized testing environment with pre-configured packages and tools to ensure consistency of test results on sonic-mgmt framework.
1. Launch the Docker for running the sonic-mgmt scripts by the following command.
    ```
    docker run -d -it -u root -h sonic -v /SONiC:/data:rslave -v "/var/run/docker.sock:/var/run/docker.sock:rslave" --name sonic sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt
    ```
2. Check docker running successfully.
    ```
    docker ps -a
    CONTAINER ID   IMAGE                                                 COMMAND       CREATED         STATUS         PORTS     NAMES
    c0daae020353   sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt   "/bin/bash"   7 seconds ago   Up 6 seconds   22/tcp    sonic
    ```
3. Check if the sonic-mgmt directory has been successfully mounted under the data folder of Docker.
    ```
    docker exec -it sonic bash
    root@sonic:/var/azureuser# ls /data
    sonic-mgmt
    ```
4. Configure the bash environment variables of Docker to support running scripts after logging into **Docker**.
    ```
    vi ./bashrc
    BASE_PATH="/data/sonic-mgmt"
    export ANSIBLE_CONFIG=${BASE_PATH}/ansible
    export ANSIBLE_LIBRARY=${BASE_PATH}/ansible/library/
    export ANSIBLE_CONNECTION_PLUGINS=${BASE_PATH}/ansible/plugins/connection
    export ANSIBLE_CLICONF_PLUGINS=${BASE_PATH}/ansible/cliconf_plugins
    export ANSIBLE_TERMINAL_PLUGINS=${BASE_PATH}/ansible/terminal_plugins
    ```
    Log in to Docker again to check if the variables take effect normally.
    ```
    docker exec -it sonic bash
    echo $BASE_PATH
    /data/sonic-mgmt
    ```
## Download and deploy PTF docker
The PTF docker container is used to send and receive data plane packets to the DUT.
1. Download PTF docker
   - Prepare the PTF docker 
   ```
   docker pull sonicdev-microsoft.azurecr.io:443/docker-ptf:latest
   ```
   or download a pre-built `docker-ptf` image [here](https://sonic-build.azurewebsites.net/api/sonic/artifacts?branchName=master&platform=vs&target=target%2Fdocker-ptf.gz) 
    ```
    docker load < docker-ptf.gz
    ```
   - Check PTF docker image on host
    ```
    docker images
    REPOSITORY                                            TAG       IMAGE ID       CREATED        SIZE
    sonicdev-microsoft.azurecr.io:443/docker-ptf          latest    6f754dd58c59   21 hours ago   2.37GB
    sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt   latest    0550f2d12fde   2 months ago   3.43GB
    ```
2. Start PTF docker
    - Launch PTF Docker through the following command. By default, do not configure the Docker network.
    ```
    docker run -d -it --name ptf_1 --network none sonicdev-microsoft.azurecr.io:443/docker-ptf
    ```
   - Check PTF container running.
    ```
    docker ps -a
    CONTAINER ID   IMAGE                                                 COMMAND                  CREATED         STATUS         PORTS     NAMES
    0723ee502496   sonicdev-microsoft.azurecr.io:443/docker-ptf          "/root/env-python3/b…"   4 seconds ago   Up 3 seconds             ptf_1
    c0daae020353   sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt   "/bin/bash"              25 hours ago    Up 25 hours    22/tcp    sonic
    ```
## Configure network for PTF
Configure a bridge network on host to link PTF to OCS. Here is the netplan method for configuring the bridged network.
1. On **host**, use netplan to build up bridge on network card.
    ```
    cat /etc/netplan/01-network-br.yaml 
    network:
    version: 2
    renderer: NetworkManager
    ethernets:
        enp0s3:
        dhcp4: no 
    bridges:
        br0:
        addresses: 
            - 192.168.1.78/24
            - '2001:db8:1::1/64'
        gateway4: 192.168.1.1
        interfaces: [enp0s3]  
        parameters:
            stp: true         
            forward-delay: 3  
    ```
    - Apply netplan.
    ```
    sudo netplan apply
    ```
    - Check that the bridged network created on the host is successful.
    ```
    # brctl show
    bridge name	bridge id		STP enabled	interfaces
    br0		8000.00e04c68007f	yes		enp0s3
    docker0		8000.86cd26814e67	no		veth9f77700
    ```
2. Build up network for PTF container.
    Create a virtual veth pair to help the PTF achieve network communication.
    First, configure on ***host***
    - Create veth pair on host
    ```
    sudo ip link add veth0 type veth peer name veth1
    ```
    - Add one of the veth interfaces, veth1, to the created bridged network br0.
    ```
    sudo brctl addif br0 veth1
    ```
    - Check the bridge configuration of br0 for veth1
    ```
    # brctl show
    bridge name	bridge id		STP enabled	interfaces
    br0		8000.00e04c68007f	yes		enp0s3
                                                            veth1
    docker0		8000.86cd26814e67	no		veth9f77700
    ``` 
    - Set veth1 up
    ```
    sudo ip link set dev veth1 up
    ``` 
    - Search the process ID of the PTF Docker.
    ```
    docker inspect --format '{{ .State.Pid }}' ptf_1
    187422
    ```
    - Configure veth0 to PTF by netns method for network namespace configuration.
    ```
    sudo ip link set veth0 netns 187422
    ```
    Then, need to login in **PTF Docker** for network configuration
    - Login into PTF to configure router
    ```
    docker exec -it ptf_1 bash
    ip addr add 192.168.1.101/24 dev veth0
    ip addr add 2001:db8:1::100/64 dev veth0
    ip link set dev veth0 up
    ```
    - Set Router in PTF
    ```
    ip route add default via 192.168.1.78 dev veth0
    ```
## Configure Inventory for OCS
In **sonic docker**, we should create OCS inventory.
Create a new OCS Inventory for OCS Testbed under */data/sonic-mgmt/ansible*

```
# vi ocs
# cat ocs
all:
  children:
    ocs:
      children:
        sonic:
          children:
            sonic_ocs:
        servers:
          children:
            vm_host:
    ptf:
      vars:
        ansible_ssh_user: root
        ansible_ssh_pass: 123456
      hosts:
        ptf_1:
          ansible_host: 192.168.1.101
sonic_ocs:
  vars:
    hwsku: SKU checked on OCS
  hosts:
    ocs-sonic:
      ansible_host: 192.168.1.3
      ansible_ssh_user: username
      ansible_ssh_pass: password
vm_host:
  hosts:
    virtualpc:
      ansible_host: 192.168.1.2
      ansible_ssh_user: testpc
      ansible_ssh_pass: 123456
```

## Configure Testbed at testbed.yaml
Also, in **sonic docker**, create new topology for OCS testbed.
```
/data/sonic-mgmt/ansible/testbed.yaml
```
Add OCS tesetbed as example:
```
- conf-name: ocs-testbed
  group-name: ptf_1
  topo: ptf64
  ptf_image_name: docker-ptf
  ptf: ptf_1
  ptf_ip: 192.168.1.101/24
  ptf_ipv6: 2001:db8:1::100/64
  server: vm_host
  dut:
    - ocs-sonic
  inv_name: ocs
  comment: testbed for ocs on sonic
```

## Use pytest to run test cases of SONiC for OCS in *sonic docker*
To run test case now, need to navigate to the tests directory of Sonic and execute the pytest command to run the specified script.
```
docker exec -it sonic bash
cd /data/sonic-mgmt/tests
```
Example of run cases for ocs topology:
```
pytest ssh/test_ssh_limit.py --inventory ../ansible/ocs --host-pattern all --testbed_file ../ansible/testbed.yaml --testbed ocs-testbed --log-cli-level debug --showlocals --assert plain --show-capture no -rav --skip_sanity --disable_loganalyzer
```  