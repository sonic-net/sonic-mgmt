# OCS Testbed Setup
This document describes the steps to setup OCS based testbed, deploy a OCS topology to it, and run a quick test to verify it is working as expected.

## Prepare testbed host
First, we need to prepare the host where we will be configuring the virtual testbed and running the tests.

1. Install Ubuntu AMD64 on your host or VM
    - To setup a OCS topology, the server needs to have at least 20GB of memory free
    - If the testbed host is a VM, then it must support nested virtualization
        - [Instructions for Hyper-V based VMs](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization#configure-nested-virtualization)
2. Prepare your environment based on Ubuntu 22.04, make sure that python and pip are installed
        update python version
        ```
        sudo apt install python3 python3-pip openssh-server
        ```
        config symbolic link:
        ```
        sudo ln -sf /usr/bin/python3 /usr/bin/python
        ```

3. Run the host setup script to install required packages and initialize the management bridge network

```
git clone https://github.com/sonic-net/sonic-mgmt
cd sonic-mgmt/ansible
sudo -H ./setup-management-network.sh
```

4. [Install Docker CE](https://docs.docker.com/install/linux/docker-ce/ubuntu/). Be sure to follow the [post-install instructions](https://docs.docker.com/install/linux/linux-postinstall/) so that you don't need sudo privileges to run docker commands.

## Setup sonic-mgmt docker
All testbed configuration steps and tests are run from a `sonic-mgmt` docker container. This container has all the necessary packages and tools for SONiC testing so that test behavior is consistent between different developers and lab setups.


1. Run the `setup-container.sh` in the root directory of the sonic-mgmt repository:

```bash
cd sonic-mgmt
./setup-container.sh -n <container name> -d /data   
```
2. (Required for IPv6 test cases): Follow the steps [IPv6 for docker default bridge](https://docs.docker.com/config/daemon/ipv6/#use-ipv6-for-the-default-bridge-network) to enable IPv6 for container. For example, edit the Docker daemon configuration file located at `/etc/docker/daemon.json` with the following parameters to use ULA address if no special requirement. Then restart docker daemon by running `sudo systemctl restart docker` to take effect.


```json
{
    "ipv6": true,
    "fixed-cidr-v6": "fd00:1::1/64",
    "experimental": true,
    "ip6tables": true
}
```

3. From now on, **all steps are running inside the sonic-mgmt docker**, unless otherwise specified.


You can enter your sonic-mgmt container with the following command:

```
docker exec -it <container name> bash
```

You will find your sonic-mgmt directory mounted at `/data/sonic-mgmt`:

```
$ ls /data/sonic-mgmt/
LICENSE  README.md  __pycache__  ansible  docs	lgtm.yml  setup-container.sh  spytest  test_reporting  tests
```
## OCS Testbed Configuration Files

### testbed_ocs_new.yaml

`testbed_ocs_new.yaml` is a specialized testbed topology configuration file designed for OCS testing environments. It should be placed in the `/sonic-mgmt/ansible` directory.This file defines the overall structure of the OCS test environment and contains the following key configuration blocks:

```
- conf-name: single-dut-ocs-testbed-demo
  group-name: ptf_2
  topo: ocs
  ptf_image_name: docker-ptf
  ptf: ptf_2
  ptf_ip: 10.250.0.189/24
  ptf_ipv6: 2001:db8:1::189
  server: server_1
  dut:
    - mgmt141
  inv_name: ocs
  comment: used to test ocs device
```

Descriptions:
- `conf-name`: Testbed configuration name, used to identify different testbed instances
- `topo: ocs`: Specifies the use of OCS-specific topology configuration
- `dut`: Defines the device list, such as mgmt141, mgmt142, etc. OCS devices
- `inv_name: ocs`: Specifies the use of OCS-specific inventory file
- `ptf`: PTF container name, used for traffic testing and packet injection
- `ptf_ip`: Management IP address for the PTF container
- `server`: Server configuration where the testbed resides

### OCS

`ocs` is the Ansible inventory file for OCS test environments, defining OCS device groups and specific device configurations:

```
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
        ptf_2:
          ansible_host: 10.250.0.189
          ansible_hostv6: 2001:db8:1::189
              
sonic_ocs:
  vars:
    hwsku: DLXA64B64HNLA1MS
  hosts:
    mgmt141: 
      ansible_host: 10.250.0.141
      ansible_gw: 10.250.0.228
      ansible_ssh_user: admin
      ansible_ssh_pass: Changeit@123
    mgmt142: 
      ansible_host: 10.250.0.142
      ansible_gw: 10.250.0.228
      ansible_ssh_user: admin
      ansible_ssh_pass: Changeit@123
    mgmt143: 
      ansible_host: 10.250.0.143
      ansible_gw: 10.250.0.228
      ansible_ssh_user: admin
      ansible_ssh_pass: Changeit@123
      
vm_host:
  hosts:
    svt:
      ansible_host: 10.192.225.188
      ansible_ssh_user: svt
      ansible_ssh_pass: 123456
servers:
  vars:
     topologies:
       - ocs
```

Descriptions:
- `sonic_ocs`: Contains all SONiC OCS devices with hardware SKU `DLXA64B64HNLA1MS`
  - `mgmt141`, `mgmt142`, `mgmt143`: OCS devices with management IPs in the 10.250.0.x range
  - Each device has gateway configuration (`ansible_gw: 10.250.0.228`)
  - Authentication uses admin/Changeit@123 credentials
- `vm_host`: Contains the virtual machine host configuration
  - `svt`: VM host server with IP 10.192.225.188 and svt/123456 credentials
- `ptf`: PTF container group for traffic testing
  - `ptf_2`: PTF container with IPv4 (10.250.0.189) and IPv6 (2001:db8:1::189) addresses
  - Uses root/123456 authentication credentials
- `servers`: Server configuration group with OCS topology definition

File Dependencies and Integration

- `testbed_ocs_new.yaml` references devices defined in the `ocs` inventory file
- The `ocs` inventory file integrates with `group_vars/ocs/` directory for additional configuration
- PTF container configuration in inventory aligns with testbed file's PTF settings
- Server topology configuration supports OCS-specific network bridging

## Setup host public key in sonic-mgmt docker
In order to configure the testbed on your host automatically, Ansible needs to be able to SSH into it without a password prompt. The `setup-container` script from the previous step will setup all the necessary SSH keys for you, but there are a few more modifications needed to make Ansible work:

1. Modify `/data/sonic-mgmt/ansible/ocs` to use the user name (e.g. `svt`) you want to use to login to the host machine (this can be your username on the host)

```
    svt:
      ansible_host: 192.168.101.188
      ansible_ssh_user: svt
      ansible_ssh_pass: 123456
```

2. Modify `/data/sonic-mgmt/ansible/ansible.cfg` to uncomment the two lines:

```
become_user='root'
become_ask_pass=False
```

3. Modify `/data/sonic-mgmt/ansible/group_vars/ocs/creds.yml` to use the username (e.g. `svt`) and password (e.g. `123456`) you want to use to login to the host machine (this can be your username and sudo password on the host). For more information about credentials variables, see: [credentials management configuration](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.new.testbed.Configuration.md#credentials-management).

```
vm_host_user: svt
vm_host_password: 123456
vm_host_become_password: 123456
```

4.  Create a dummy `password.txt` file under `/data/sonic-mgmt/ansible`
    - **Note**: Here, `password.txt` is the Ansible Vault password file. Ansible allows users to use Ansible Vault to encrypt password files.

      By default, the testbed scripts require a password file. If you are not using Ansible Vault, you can create a file with a dummy password (e.g. `abc`) and pass the filename to the command line. The file name and location is created and maintained by the user.

5. On the **host**, run `sudo visudo` and add the following line at the end:

```
svt ALL=(ALL) NOPASSWD:ALL
```
6. Verify that you can use `sudo` without a password prompt inside the **host** (e.g. `sudo bash`).

## Deploy OCS topology
Create a `topo_ocs.yml` file under `/data/sonic-mgmt/ansible/vars`
```
topology:
  host_interfaces:
   - 0
   - 1
   - 2
   - 3
   - 4
   - 5
   - 6
   - 7
   - 8
   - 9
   - 10
   - 11
   - 12
   - 13
   - 14
   - 15
   - 16
   - 17
   - 18
   - 19
   - 20
   - 21
   - 22
   - 23
   - 24
   - 25
   - 26
   - 27
   - 28
   - 29
   - 30
   - 31
   - 32
   - 33
   - 34
   - 35
   - 36
   - 37
   - 38
   - 39
   - 40
   - 41
   - 42
   - 43
   - 44
   - 45
   - 46
   - 47
   - 48
   - 49
   - 50
   - 51
   - 52
   - 53
   - 54
   - 55
   - 56
   - 57
   - 58
   - 59
   - 60
   - 61
   - 62
   - 63
```
Now we're finally ready to deploy the topology for our testbed! Run the following command:

./testbed-cli.sh -t testbed_ocs_new.yaml -m ocs add-topo single-dut-ocs-testbed-demo password.txt

Verify that the PTF was created properly:

```
$ docker ps
CONTAINER ID   IMAGE                          COMMAND                  CREATED      STATUS      PORTS     NAMES
6a02555acdb7   docker-ptf:latest              "/usr/local/bin/supe…"   2 days ago   Up 2 days             ptf_2

```
If you want to configure the network for PTF, you can put the file `config_ptf_network.sh` under `/home/hong/sonic-mgmt/ansible/` and use the following command:

```
./config_ptf_network.sh --server-interface enp0s3 --vm-set-name ptf_2 --ptf-ip 10.250.0.189/24 --mgmt-gw 10.250.0.228
```
If you need to modify the parameters, such as using different server interfaces or IP addresses, simply adjust the corresponding parameter values.

You're now set up and ready to use the OCS testbed!
