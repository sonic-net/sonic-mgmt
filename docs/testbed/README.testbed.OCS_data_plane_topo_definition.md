OCS data plane topology definition
==================================

  -------------- --------------------- ---------------
  Date           Author                Comments
  July 9, 2025   Huang Xin, SVT team   Initial draft
  -------------- --------------------- ---------------

1. Purpose
----------

This document defines the topology of the Optical Circuit Switch (OCS)
data plane, specifying the physical structure, connectivity and
performance parameters to ensure reliable optical signal transmission

2. Scope
--------

This topology definition covers:

-   Physical fiber and node layout

-   Enable flexible reconfiguration of optical paths (Main objective)

-   Provide high-bandwidth, low-latency connectivity

3. Physical Topology Components
-------------------------------

![图示 AI
生成的内容可能不正确。](media/image1.png){width="5.768055555555556in"
height="4.6715277777777775in"}

### 3.1 OCS 

-   **Optical Switch Matrix**: 64×64 port configuration

### 3.2 Endpoint Connections

-   **Server Connections (Dell R760XS)**:

    -   2 CPUs each has 24 cores (48 cores);

    -   192G memory (16Gx12);

    -   hard disk:960Gx1

    -   Mellanox CX6 (NIC)

        -   ConnectX-6 DX 100GbE Dual Port

        -   ConnectX-6 100GbE Single Port

-   **Root Fanout:**

    -   **Arista-7260CX3-64**

        -   64 ports, 12.8T

        -   Supports LACP/LLDP passthrough

        -   Supports 802.1Q tunning (QinQ)

-   **Leaf Fanout: **

    -   **Arista 7060X6-64PE: (2U)**

        -   64X800GbE OSFP ports, 2SFP+ports

        -   64 ports 800G, 51.2T

        -   Migrate to 320 interfaces

        -   Supports LACP/LLDP passthrough

        -   Supports 802.1Q tunning (QinQ)

-   **Network Gateway Connections**:

    -   Inter-switch links to routers

4.Testing Objectives
--------------------

-   Full mesh capability

    -   any-to-any connectivity

    -   64x64 Simultaneous connectivity Test

-   Dynamic path provisioning

5. Deploy an OCS Testbed
------------------------

### Prepare Testbed host

According to testbed.Setup\[testbed.Setup\], prepare a PC with Ubuntu
20.04(recommended), install the necessary libraries, and download
sonic-mgmt docker container for test scripts running as well as a PTF
container for service distribution.

1.  Install Ubuntu AMD64 on your host or VM

    -   The host PC needs to have at least 20GB of memory free

    -   If the testbed host is a VM, then it must support nested
        virtualization

        -   [**[Instructions for Hyper-V based
            VMs]{.underline}**](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization#configure-nested-virtualization)

2.  Prepare your environment based on Ubuntu, The Ubuntu version now is
    recommended with **Ubuntu 20.04**

-   sudo apt install python3 python3-pip openssh-server

    If checked the default python version with command python -version,
    the python version on server now is still 2.x. After installing
    python3, replace python command with python3 using symbolic link:

    sudo ln -sf /usr/bin/python3 /usr/bin/python

    For more Ubuntu version, running this testbed needs to be explored
    for compatibility.

3.  Download the latest version of sonic-mgmt on GitHub Create a folder
    to store the cloned files of sonic-mgmt test scripts.

-   cd \~\
    mkdir SONiC\
    chmod 777 SONiC\
    git clone https://github.com/sonic-net/sonic-mgmt

    Check download script in folder:

    /SONiC\# ls\
    sonic-mgmt\
    /SONiC/sonic-mgmt\# ls\
    ansible azure-pipelines.yml docs LICENSE pylintrc pyproject.toml
    README.md sdn\_tests SECURITY.md setup-container.sh
    sonic\_dictionary.txt spytest test\_reporting tests

4.  [**[Install Docker
    CE]{.underline}**](https://docs.docker.com/install/linux/docker-ce/ubuntu/).
    Be sure to follow the [**[post-install
    instructions]{.underline}**](https://docs.docker.com/install/linux/linux-postinstall/)
    so that you don\'t need sudo privileges to run docker commands.

### Download sonic-mgmt docker container

1.  The simplest way to run the script on testbed is to deploy the
    official Docker and run cases within the Docker, so there is no need
    to deploy the required runtime libraries separately.

    -   Build the test environment on sonic-vs container.

-   docker pull
    sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest

2.  Check if the Docker image has been installed on host.

-   docker images\
    REPOSITORY TAG IMAGE ID CREATED SIZE\
    sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt latest
    0550f2d12fde 2 months ago 3.43GB

### Setup sonic-mgmt docker

All testbed configurations and test procedures execute within a
sonic-mgmt Docker container, providing a standardized testing
environment with pre-configured packages and tools to ensure consistency
of test results on sonic-mgmt framework.

1.  Launch the Docker for running the sonic-mgmt scripts by the
    following command.

-   docker run -d -it -u root -h sonic -v /SONiC:/data:rslave -v
    \"/var/run/docker.sock:/var/run/docker.sock:rslave\" \--name sonic
    sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt

2.  Check docker running successfully.

-   docker ps -a\
    CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES\
    c0daae020353 sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt
    \"/bin/bash\" 7 seconds ago Up 6 seconds 22/tcp sonic

3.  Check if the sonic-mgmt directory has been successfully mounted
    under the data folder of Docker.

-   docker exec -it sonic bash\
    root\@sonic:/var/azureuser\# ls /data\
    sonic-mgmt

4.  Configure the bash environment variables of Docker to support
    running scripts after logging into **Docker**.

-   vi ./bashrc\
    BASE\_PATH=\"/data/sonic-mgmt\"\
    export ANSIBLE\_CONFIG=\${BASE\_PATH}/ansible\
    export ANSIBLE\_LIBRARY=\${BASE\_PATH}/ansible/library/\
    export
    ANSIBLE\_CONNECTION\_PLUGINS=\${BASE\_PATH}/ansible/plugins/connection\
    export
    ANSIBLE\_CLICONF\_PLUGINS=\${BASE\_PATH}/ansible/cliconf\_plugins\
    export
    ANSIBLE\_TERMINAL\_PLUGINS=\${BASE\_PATH}/ansible/terminal\_plugins

    Log in to Docker again to check if the variables take effect
    normally.

    docker exec -it sonic bash\
    echo \$BASE\_PATH\
    /data/sonic-mgmt

### Download and deploy PTF docker

The PTF docker container is used to send and receive data plane packets
to the DUT.

1.  Download PTF docker

    -   Prepare the PTF docker

-   docker pull sonicdev-microsoft.azurecr.io:443/docker-ptf:latest

    or download a pre-built docker-ptf image
    [**[here]{.underline}**](https://sonic-build.azurewebsites.net/api/sonic/artifacts?branchName=master&platform=vs&target=target%2Fdocker-ptf.gz)

    docker load \< docker-ptf.gz

    -   Check PTF docker image on host

    docker images\
    REPOSITORY TAG IMAGE ID CREATED SIZE\
    sonicdev-microsoft.azurecr.io:443/docker-ptf latest 6f754dd58c59 21
    hours ago 2.37GB\
    sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt latest
    0550f2d12fde 2 months ago 3.43GB

2.  Start PTF docker

    -   Launch PTF Docker through the following command. By default, do
        not configure the Docker network.

-   docker run -d -it -name ptf\_1 \--network none
    sonicdev-microsoft.azurecr.io:443/docker-ptf

    -   Check PTF container running.

    docker ps -a\
    CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES\
    0723ee502496 sonicdev-microsoft.azurecr.io:443/docker-ptf
    \"/root/env-python3/bâ€¦\" 4 seconds ago Up 3 seconds ptf\_1\
    c0daae020353 sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt
    \"/bin/bash\" 25 hours ago Up 25 hours 22/tcp sonic

### Configure network for PTF

Configure a bridge network on host to link PTF to OCS. Here is the
netplan method for configuring the bridged network.

1.  On **host**, use netplan to build up bridge on network card.

-   cat /etc/netplan/01-network-br.yaml\
    network:\
    version: 2\
    renderer: NetworkManager\
    ethernets:\
    enp0s3:\
    dhcp4: no\
    bridges:\
    br0:\
    addresses:\
    - 192.168.1.78/24\
    - \'2001:db8:1::1/64\'\
    gateway4: 192.168.1.1\
    interfaces: \[enp0s3\]\
    parameters:\
    stp: true\
    forward-delay: 3

    -   Apply netplan.

    sudo netplan apply

    -   Check that the bridged network created on the host is
        successful.

    \# brctl show\
    bridge name bridge id STP enabled interfaces\
    br0 8000.00e04c68007f yes enp0s3\
    docker0 8000.86cd26814e67 no veth9f77700

2.  Build up the network for PTF container. Create a virtual veth pair
    to help PTF achieve network communication. First, configure on
    ***host***

    -   Create veth pair on host

-   sudo ip link add veth0 type veth peer name veth1

    -   Add one of the veth interfaces, veth1, to the created bridged
        network br0.

    sudo brctl addif br0 veth1

    -   Check the bridge configuration of br0 for veth1

    \# brctl show\
    bridge name bridge id STP enabled interfaces\
    br0 8000.00e04c68007f yes enp0s3\
    veth1\
    docker0 8000.86cd26814e67 no veth9f77700

    -   Set veth1 up

    sudo ip link set dev veth1 up

    -   Search the process ID of the PTF Docker.

    docker inspect \--format \'{{ .State.Pid }}\' ptf\_1\
    187422

    -   Configure veth0 to PTF by netns method for network namespace
        configuration.

    sudo ip link set veth0 netns 187422

    Then, need to login in **PTF Docker** for network configuration

    -   Login into PTF to configure router

    docker exec -it ptf\_1 bash\
    ip addr add 192.168.1.101/24 dev veth0\
    ip addr add 2001:db8:1::100/64 dev veth0\
    ip link set dev veth0 up

    -   Set Router in PTF

    ip route add default via 192.168.1.78 dev veth0

### Configure Inventory for OCS

In **sonic docker**, we should create OCS inventory. Create a new OCS
Inventory for OCS Testbed under */data/sonic-mgmt/ansible*

\# vi ocs\
\# cat ocs\
all:\
children:\
ocs:\
children:\
sonic:\
children:\
sonic\_ocs:\
servers:\
children:\
vm\_host:\
ptf:\
vars:\
ansible\_ssh\_user: root\
ansible\_ssh\_pass: 123456\
hosts:\
ptf\_1:\
ansible\_host: 192.168.1.101\
sonic\_ocs:\
vars:\
hwsku: SKU checked on OCS\
hosts:\
ocs-sonic:\
ansible\_host: 192.168.1.3\
ansible\_ssh\_user: username\
ansible\_ssh\_pass: password\
vm\_host:\
hosts:\
virtualpc:\
ansible\_host: 192.168.1.2\
ansible\_ssh\_user: testpc\
ansible\_ssh\_pass: 123456

### Configure Testbed at testbed.yaml

Also, in **sonic docker**, create new topology for OCS testbed.

/data/sonic-mgmt/ansible/testbed.yaml

Add OCS tesetbed as example:

\- conf-name: ocs-testbed\
group-name: ptf\_1\
topo: ptf64\
ptf\_image\_name: docker-ptf\
ptf: ptf\_1\
ptf\_ip: 192.168.1.101/24\
ptf\_ipv6: 2001:db8:1::100/64\
server: vm\_host\
dut:\
- ocs-sonic\
inv\_name: ocs\
comment: testbed for ocs on sonic

***Use pytest to run test cases of SONiC for OCS in sonic docker***

To run test case now, Tester need to navigate to the tests directory of
Sonic and execute the pytest command to run the specified script.

docker exec -it sonic bash\
cd /data/sonic-mgmt/tests

Example of run cases for ocs topology:

pytest ssh/test\_ssh\_limit.py \--inventory ../ansible/ocs
\--host-pattern all \--testbed\_file ../ansible/testbed.yaml \--testbed
ocs-testbed \--log-cli-level debug \--showlocals \--assert plain
\--show-capture no -rav \--skip\_sanity \--disable\_loganalyzer
