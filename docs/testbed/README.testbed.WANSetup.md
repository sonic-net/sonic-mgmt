# KVM Multiple Devices Testbed Setup
This document describes the steps to setup a virtual switch based testbed, deploy a multiple devices and multiple protocols topology to it, and run a quick test to verify it is working as expected.

## Prepare testbed host
First, we need to prepare the host where we will be configuring the virtual testbed and running the tests.

1. Install Ubuntu AMD64 on your host or VM
    - To setup a multiple devices topology, the server needs to have at least 20GB (96GB if you deploy multiple cisco devices topology) of memory free
    - If the testbed host is a VM, then it must support nested virtualization
        - [Instructions for Hyper-V based VMs](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization#configure-nested-virtualization)
2. Prepare your environment based on Ubuntu 20.04, make sure that python and pip are installed
        ```
        sudo apt install python3 python3-pip openssh-server
        ```
        If the server was upgraded from Ubuntu 18.04, check the default python version using command `python --version`. If the default python version is still 2.x, replace it with python3 using symbolic link:
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

## Download an VM image
We currently support IOS-XR-based, EOS-based or SONiC VMs to simulate neighboring devices in the virtual testbed, much like we do for physical testbeds. To do so, we need to download the image to our testbed host.

### Option 1: cEOS (container-based) image (recommended)

1. **Prepare folder for image files on test server**

    Create a subfolder called `images` inside the `root_path` directory defined in `ansible/group_vars/vm_host/main.yml` file. For instance, if `root_path` is set to `veos-vm`, you should run the following command:

    ```bash
    mkdir -p ~/veos-vm/images
    ```

2. **Prepare the cEOS image file**

   #### Option 1.1: Manually download cEOS image

   1. Obtain the cEOS image from [Arista's software download page](https://www.arista.com/en/support/software-download).
   2. Place the image file in the `images` subfolder located within the directory specified by the `root_path` variable in the `ansible/group_vars/vm_host/main.yml` file.

      Assuming you set `root_path` to `veos-vm`, you should run the following command:

      ```bash
      cp cEOS64-lab-4.29.3M.tar ~/veos-vm/images/
      ```
      The Ansible playbook for deploying testbed topology will automatically use the manually prepared image file from this location.

   #### Option 1.2: Host the cEOS image file on a HTTP server
   If you need to deploy VS setup on multiple testbed hosts, this option is more recommended.

   1. **Download the cEOS Image**

      Obtain the cEOS image from [Arista's software download page](https://www.arista.com/en/support/software-download).

   2. **Host the cEOS Image**

      Host the cEOS image file on an HTTP server. Ensure that the image file is accessible via HTTP from the `sonic-mgmt` container running the testbed deployment code. For example, the URL might look like `http://192.168.1.10/cEOS64-lab-4.29.3M.tar`.

   3. **Update the Ansible Configuration**

      Update the `ceos_image_url` variable in `ansible/group_vars/vm_host/ceos.yml` with the URL of the cEOS image. This variable can be a single string for one URL or a list of strings for multiple URLs.

      The Ansible playbook will attempt to download the image from each URL in the list until it succeeds. Downloaded file is stored to `images` subfolder of the location determined by `root_path` variable in `ansible/group_vars/vm_host/main.yml`. For example if `root_path` is `/data/veos-vm`, then the downloaded image file is put to `/data/veso-vm/images`

      Variable `skip_ceos_image_downloading` in `ansible/group_vars/vm_host/ceos.yml` also must be set to `false` if you wish ansible playbook to automatically try downloading cEOS image file. For example
      ```yaml
      ceos_image_url: http://192.168.1.10/cEOS64-lab-4.29.3M.tar
      skip_ceos_image_downloading: false
      ```
      Or:
      ```yaml
      ceos_image_url:
         - http://192.168.1.10/cEOS64-lab-4.29.3M.tar
      skip_ceos_image_downloading: false
      ```

**Note** When downloading, the version specified above might be outdated or unavailable. Please check the [Arista recommended release](https://www.arista.com/en/support/software-download#datatab300) to obtain the latest recommended image and import it into your local Docker registry.
The actual image version that is needed in the installation process is defined in the file [ansible/group_vars/vm_host/ceos.yml](../../ansible/group_vars/vm_host/ceos.yml), make sure you modify locally to keep it up with the image version you imported.*

**Note**: Please be aware of the image's CPU architecture (32 vs 64-bit). In the example above, it is a standard 64-bit cEOS image. Ensure you import the correct image according to your requirements.

### Option 2: Use Cisco image as neighboring devices
You need to prepare a Cisco IOS-XR image `cisco-vs.img` in `~/veos-vm/images/`.The actual image version that is needed in the installation process is defined in the file [ansible/group_vars/vm_host/main.yml:cisco_image_filename](../../ansible/group_vars/vm_host/main.yml). We don't support to download cisco image automatically, you can download an available image from [Download Cisco image](https://software.cisco.com/download/home/282414851/type/280805694/release/7.6.2) and put it into the directory `~/veos-vm/images`


## Download the sonic-vs image
To run the tests with a virtual SONiC device, we need a virtual SONiC image. The simplest way to do so is to download the latest succesful build.

1. Download the sonic-vs image from [here](https://sonic-build.azurewebsites.net/api/sonic/artifacts?branchName=master&platform=vs&target=target/sonic-vs.img.gz)

   ```
   wget "https://sonic-build.azurewebsites.net/api/sonic/artifacts?branchName=master&platform=vs&target=target/sonic-vs.img.gz" -O sonic-vs.img.gz
   ```

2. Unzip the image and copy it into `~/sonic-vm/images/` and also `~/veos-vm/images`

   ```
   gzip -d sonic-vs.img.gz
   mkdir -p ~/sonic-vm/images
   cp sonic-vs.img ~/sonic-vm/images
   mv sonic-vs.img ~/veos-vm/images
   ```

## Setup sonic-mgmt docker
All testbed configuration steps and tests are run from a `sonic-mgmt` docker container. This container has all the necessary packages and tools for SONiC testing so that test behavior is consistent between different developers and lab setups.

1. Run the `setup-container.sh` in the root directory of the sonic-mgmt repository:

   ```
   cd sonic-mgmt
   ./setup-container.sh -n <container name> -d /data
   ```

2. From now on, **all steps are running inside the sonic-mgmt docker**, unless otherwise specified.


You can enter your sonic-mgmt container with the following command:

   ```
   docker exec -it <container name> bash
   ```

You will find your sonic-mgmt directory mounted at `/data/sonic-mgmt`:

   ```
   $ ls /data/sonic-mgmt/
   LICENSE  README.md  __pycache__  ansible  docs	lgtm.yml  setup-container.sh  spytest  test_reporting  tests
   ```

## Setup host public key in sonic-mgmt docker
In order to configure the testbed on your host automatically, Ansible needs to be able to SSH into it without a password prompt. The `setup-container` script from the previous step will setup all the necessary SSH keys for you, but there are a few more modifications needed to make Ansible work:

1. Modify `/data/sonic-mgmt/ansible/veos_vtb` to use the user name (e.g. `foo`) you want to use to login to the host machine (this can be your username on the host)

   ```
   foo@sonic:/data/sonic-mgmt/ansible$ git diff
   diff --git a/ansible/veos_vtb b/ansible/veos_vtb
   index 3e7b3c4e..edabfc40 100644
   --- a/ansible/veos_vtb
   +++ b/ansible/veos_vtb
   @@ -258,7 +258,7 @@ vm_host_1:
        STR-ACS-VSERV-01:
          ansible_host: 172.17.0.1
          ansible_user: use_own_value
   -      vm_host_user: use_own_value
   +      vm_host_user: foo

   vms_1:
      hosts:
   ```

2.  Create a dummy `password.txt` file under `/data/sonic-mgmt/ansible`
    - **Note**: Here, `password.txt` is the Ansible Vault password file. Ansible allows users to use Ansible Vault to encrypt password files.

      By default, the testbed scripts require a password file. If you are not using Ansible Vault, you can create a file with a dummy password (e.g. `abc`) and pass the filename to the command line. The file name and location is created and maintained by the user.

3. On the **host**, run `sudo visudo` and add the following line at the end:

   ```
   foo ALL=(ALL) NOPASSWD:ALL
   ```

4. Verify that you can login into the **host** (e.g. `ssh foo@172.17.0.1`, if the default docker bridge IP is `172.18.0.1/16`, follow https://docs.docker.com/network/bridge/#configure-the-default-bridge-network to change it to `172.17.0.1/16`, delete the current `sonic-mgmt` docker using command `docker rm -f <sonic-mgmt_container_name>`, then start over from step 1 of section **Setup sonic-mgmt docker** ) from the `sonic-mgmt` **container** without any password prompt.

5. Verify that you can use `sudo` without a password prompt inside the **host** (e.g. `sudo bash`).


## Deploy multiple devices topology
Now we're finally ready to deploy the topology for our testbed! Run the following command:

(Optional) The connectivity to the public internet is necessary during the setup, if the lab env of your organization requires http/https proxy server to reach out to the internet, you need to configure to use the proxy server. It will automatically be leveraged on required steps (e.g. Docker daemon config for image pulling, APT configuration for installing packages). You can configure it in [`ansible/group_vars/all/env.yml`](https://github.com/sonic-net/sonic-mgmt/blob/master/ansible/group_vars/all/env.yml)

### cEOS
   ```
   cd /data/sonic-mgmt/ansible
   ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k ceos add-topo vms-kvm-wan-pub password.txt
   ```

Verify that the cEOS neighbors were created properly:

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


### Cisco
Now we need to spin up some VMs on the host to act as neighboring devices to our virtual SONiC switch.

1. Start the VMs:
   ```
   ./testbed-cli.sh -m veos_vtb -k vcisco -t vtestbed.yaml start-topo-vms vms-kvm-wan-pub-cisco password.txt
   ```

   Verify that the vcisco neighbors were created properly:
   Because cisco devices can't run ansible module smoothly, we can manually ssh to these VMs to verify whether devices startup normally.

2. Deploy topology
   ```
   cd /data/sonic-mgmt/ansible
   ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k vcisco add-topo vms-kvm-wan-pub-cisco password.txt
   ```

## Deploy configuration on the devices
Once the topology has been created, we need to give the devices an initial configuration.

   cEOS:
   ```
   ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb deploy-mg vms-kvm-wan-pub veos_vtb password.txt
   ```
   cisco:
   ```
   ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb deploy-mg vms-kvm-wan-pub-cisco veos_vtb password.txt
   ```


Verify the DUT is created successfully. In your host run
   ```
   ~$ virsh list
    Id   Name      State
   -------------------------
    3    vlab-01   running
   ```
 Then you can try to login to your dut through the command and get logged in as shown below.
 For more information about how to get the DUT IP address, please refer to doc
 [testbed.Example#access-the-dut](README.testbed.Example.Config.md#access-the-dut)
   ```
   ~$ ssh admin@10.250.0.101
   admin@10.250.0.101's password:
   Linux vlab-01 4.19.0-12-2-amd64 #1 SMP Debian 4.19.152-1 (2020-10-18) x86_64
   You are on
    ____   ___  _   _ _  ____
   / ___| / _ \| \ | (_)/ ___|
   \___ \| | | |  \| | | |
    ___) | |_| | |\  | | |___
   |____/ \___/|_| \_|_|\____|

   -- Software for Open Networking in the Cloud --

   Unauthorized access and/or use are prohibited.
   All access and/or use are subject to monitoring.

   Help:    http://azure.github.io/SONiC/

   Last login: Thu Jul 29 03:55:53 2021 from 10.250.0.1
   admin@vlab-01:~$ exit
   ```

2. Verify that you can login to the SONiC KVM using Mgmt IP = 10.250.0.101 and admin:password.
   ```
   ssh admin@10.250.0.101
   admin@10.250.0.101's password: password
   ```
3. After logged in to the SONiC KVM, you should be able to see IP interfaces with:
   ```
   show ip int
   ```

   ```
   admin@vlab-01:~$ show ip int
   Interface       Master    IPv4 address/mask    Admin/Oper    BGP Neighbor    Neighbor IP
   --------------  --------  -------------------  ------------  --------------  -------------
   Loopback0                 10.1.0.32/32         up/up         N/A             N/A
   PortChannel101            10.0.0.56/31         up/up         N/A             N/A
   PortChannel102            10.0.0.58/31         up/up         N/A             N/A
   docker0                   240.127.1.1/24       up/down       N/A             N/A
   eth0                      10.250.0.101/24      up/up         N/A             N/A
   lo                        127.0.0.1/16         up/up         N/A             N/A
   admin@vlab-01:~$
   ```


## Run a Pytest
Now that the testbed has been fully setup and configured, let's run a simple test to make sure everything is functioning as expected.

1. Switch over to the `tests` directory:

   ```
   cd sonic-mgmt/tests
   ```

2. Run the following command to execute the `lldp` test (including the pre/post setup steps):

If neighbor devices are EOS

   ```
   ./run_tests.sh -m group -a False -n vms-kvm-wan-pub -u -d vlab-01 -c wan/lldp/ -f vtestbed.yaml -i veos_vtb -e "--neighbor_type=eos --disable_loganalyzer --skip_sanity"
   ```

If neighbor devices are Cisco

   ```
   ./run_tests.sh -m group -a False -n vms-kvm-wan-pub-cisco -u -d vlab-01 -c wan/lldp/ -f vtestbed.yaml -i veos_vtb -e "--neighbor_type=cisco --disable_loganalyzer --skip_sanity"
   ```
You should see tests run and pass. You're now set up and ready to use the KVM testbed!

## Restore/Remove the testing environment
If you want to clear your testing environment, you can log into your mgmt docker that you created at step three in section [Prepare testbed host](README.testbed.WANSetup.md#prepare-testbed-host).

Then run command:
   For cEOS neighbor:
   ```
   ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k ceos remove-topo vms-kvm-wan-pub password.txt
   ```
   For cisco neighbor:
   ```
   ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k vcisco remove-topo vms-kvm-wan-pub-cisco password.txt
   ```
