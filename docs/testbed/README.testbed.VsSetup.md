# KVM Testbed Setup
This document describes the steps to setup a virtual switch based testbed, deploy a T0 topology to it, and run a quick test to verify it is working as expected.

## Prepare testbed host
First, we need to prepare the host where we will be configuring the virtual testbed and running the tests.

1. Install Ubuntu AMD64 on your host or VM
    - To setup a T0 topology, the server needs to have at least 10GB of memory free
    - If the testbed host is a VM, then it must support nested virtualization
        - [Instructions for Hyper-V based VMs](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization#configure-nested-virtualization)
2. Prepare your environment based on different Ubuntu version, make sure that python and pip are installed
   1. Option : If your host is **Ubuntu 20.04**
        
        ```
        sudo apt install python3 python3-pip
        ```
        If the server was upgraded from Ubuntu 18.04, check the default python version using command `python --version`. If the default python version is still 2.x, replace it with python3 using symbolic link:
        ```
        sudo ln -sf /usr/bin/python3 /usr/bin/python
        ```
   2. Option : If your host is **Ubuntu 18.04**
        ```
        sudo apt install python python-pip
        # v0.3.12b Jinja2 is required, lower version may cause uncompatible issue
        sudo pip install j2cli==0.3.12b0
        ```

3. Run the host setup script to install required packages and initialize the management bridge network

```
git clone https://github.com/Azure/sonic-mgmt
cd sonic-mgmt/ansible
sudo ./setup-management-network.sh
```

4. [Install Docker CE](https://docs.docker.com/install/linux/docker-ce/ubuntu/). Be sure to follow the [post-install instructions](https://docs.docker.com/install/linux/linux-postinstall/) so that you don't need sudo privileges to run docker commands.

## Download an VM image
We currently support EOS-based or SONiC VMs to simulate neighboring devices in the virtual testbed, much like we do for physical testbeds. To do so, we need to download the image to our testbed host.

### Option 1: vEOS (KVM-based) image
1. Download the [vEOS image from Arista](https://www.arista.com/en/support/software-download)
2. Copy below image files to `~/veos-vm/images` on your testbed host:
   - `Aboot-veos-serial-8.0.0.iso`
   - `vEOS-lab-4.20.15M.vmdk`
### Option 2: cEOS (container-based) image (experimental)
#### Option 2.1: Download and import cEOS image manually
1. Download the [cEOS image from Arista](https://www.arista.com/en/support/software-download)
2. Import the cEOS image (it will take several minutes to import, so please be patient!)

```
docker import cEOS-lab-4.25.5.1M.tar.xz ceosimage:4.25.5.1M-1
```
After imported successfully, you can check it by 'docker images'
```
$ docker images
REPOSITORY                                             TAG           IMAGE ID       CREATED         SIZE
ceosimage                                              4.25.5.1M-1   fa0df4b01467   9 seconds ago   1.62GB
```
**Note**: *For time being, the image might be updated, the actual image version that is needed in the installation process is defined in the file [ansible/group_vars/all/ceos.yml](../../ansible/group_vars/all/ceos.yml), please download the corresponding version of image and import it to your local docker repository.*

**Note**: *Please also notice the type of the bit for the image, in the example above, it is a standard 32-bit image. Please import the right image as your needs.*
#### Option 2.2: Pull cEOS image automatically
1. Alternatively, you can host the cEOS image on a http server. Specify `vm_images_url` for downloading the image [here](https://github.com/Azure/sonic-mgmt/blob/master/ansible/group_vars/vm_host/main.yml#L2).

2. If a SAS key is required for downloading the cEOS image, specify `ceosimage_saskey` in `sonic-mgmt/ansible/vars/azure_storage.yml`.

If you want to skip downloading the image when the cEOS image is not imported locally, set `skip_ceos_image_downloading` to `true` in `sonic-mgmt/ansible/group_vars/all/ceos.yml`. Then, when the cEOS image is not locally available, the scripts will not try to download it and will fail with an error message. Please use option 1 to download and import the cEOS image manually.

#### Option 3: Use SONiC image as neighboring devices
You need to prepare a sound SONiC image `sonic-vs.img` in `~/veos-vm/images/`. We don't support to download sound sonic image right now, but for testing, you can also follow the section [Download the sonic-vs image](##download-the-sonic-vs-image) to download an available image and put it into the directory `~/veos-vm/images`

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
@@ -73,7 +73,7 @@ vm_host_1:
   hosts:
     STR-ACS-VSERV-01:
       ansible_host: 172.17.0.1
-      ansible_user: use_own_value
+      ansible_user: foo

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

## Setup VMs on the server
**(Skip this step if you are using cEOS - the containers will be automatically setup in a later step.)**

Now we need to spin up some VMs on the host to act as neighboring devices to our virtual SONiC switch.

1. Start the VMs:
```
./testbed-cli.sh -m veos_vtb -n 4 start-vms server_1 password.txt
```
If you use SONiC image as the neighbor devices (***Not DUT***), you need to add extra parameters `-k vsonic` so that this command is `./testbed-cli.sh -m veos_vtb -n 4 -k vsonic start-vms server_1 password.txt`. Of course, if you want to stop VMs, you also need to append these parameters after original command.

- **Reminder:** By default, this shell script requires a password file. If you are not using Ansible Vault, just create a file with a dummy password and pass the filename to the command line.


2. Check that all VMs are up and running.
For the EOS-based VMs **Note:** The passwd is `123456`.
```
$ ansible -m ping -i veos_vtb server_1 -u root -k
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
For the SONiC VMs **Note:** The passwd is `password`.
```
$ ansible -m ping -i veos_vtb server_1 -u admin -k
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
Now we're finally ready to deploy the topology for our testbed! Run the following command, depending on what type of EOS image you are using for your setup:

### vEOS
```
cd /data/sonic-mgmt/ansible
./testbed-cli.sh -t vtestbed.csv -m veos_vtb add-topo vms-kvm-t0 password.txt
```

### cEOS
```
cd /data/sonic-mgmt/ansible
./testbed-cli.sh -t vtestbed.csv -m veos_vtb -k ceos add-topo vms-kvm-t0 password.txt
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

### vSONiC
```
cd /data/sonic-mgmt/ansible
./testbed-cli.sh -t vtestbed.csv -m veos_vtb -k vsonic add-topo vms-kvm-t0 password.txt
```

## Deploy minigraph on the DUT
Once the topology has been created, we need to give the DUT an initial configuration.

1. Deploy the `minigraph.xml` to the DUT and save the configuration:

```
./testbed-cli.sh -t vtestbed.csv -m veos_vtb deploy-mg vms-kvm-t0 veos_vtb password.txt
```

2. Verify that you can login to the SONiC KVM using Mgmt IP = 10.250.0.101 and admin:password.
```
ssh admin@10.250.0.101
admin@10.250.0.101's password: password
```
3. After logged in to the SONiC KVM, you should be able to see BGP sessions with:
```
show ip bgp sum
```
If neighbor devices are EOS:

```
admin@vlab-01:~$ show ip bgp sum

IPv4 Unicast Summary:
BGP router identifier 10.1.0.32, local AS number 65100 vrf-id 0
BGP table version 6405
RIB entries 12807, using 2458944 bytes of memory
Peers 4, using 87264 KiB of memory
Peer groups 4, using 256 bytes of memory


Neighbhor      V     AS    MsgRcvd    MsgSent    TblVer    InQ    OutQ  Up/Down      State/PfxRcd  NeighborName
-----------  ---  -----  ---------  ---------  --------  -----  ------  ---------  --------------  --------------
10.0.0.57      4  64600       3792       3792         0      0       0  00:29:24             6400  ARISTA01T1
10.0.0.59      4  64600       3792       3795         0      0       0  00:29:24             6400  ARISTA02T1
10.0.0.61      4  64600       3792       3792         0      0       0  00:29:24             6400  ARISTA03T1
10.0.0.63      4  64600       3795       3796         0      0       0  00:29:24             6400  ARISTA04T1

Total number of neighbors 4
```

If neighbor devices are SONiC

```
admin@vlab-01:~$ show ip bgp sum

IPv4 Unicast Summary:
BGP router identifier 10.1.0.32, local AS number 65100 vrf-id 0
BGP table version 3
RIB entries 5, using 920 bytes of memory
Peers 4, using 83680 KiB of memory
Peer groups 4, using 256 bytes of memory


Neighbhor      V     AS    MsgRcvd    MsgSent    TblVer    InQ    OutQ  Up/Down    State/PfxRcd    NeighborName
-----------  ---  -----  ---------  ---------  --------  -----  ------  ---------  --------------  --------------
10.0.0.57      4  64600          8          8         0      0       0  00:00:10   3               ARISTA01T1
10.0.0.59      4  64600          0          0         0      0       0  00:00:10   3               ARISTA02T1
10.0.0.61      4  64600          0          0         0      0       0  00:00:11   3               ARISTA03T1
10.0.0.63      4  64600          0          0         0      0       0  00:00:11   3               ARISTA04T1

```

## Run a Pytest
Now that the testbed has been fully setup and configured, let's run a simple test to make sure everything is functioning as expected.

1. Switch over to the `tests` directory:

```
cd sonic-mgmt/tests
```

2. Run the following command to execute the `bgp_fact` test (including the pre/post setup steps):

If neighbor devices are EOS

```
./run_tests.sh -n vms-kvm-t0 -d vlab-01 -c bgp/test_bgp_fact.py -f vtestbed.csv -i veos_vtb
```

If neighbor devices are SONiC

```
./run_tests.sh -n vms-kvm-t0 -d vlab-01 -c bgp/test_bgp_fact.py -f vtestbed.csv -i veos_vtb -e "--neighbor_type=sonic"
```

You should see three sets of tests run and pass. You're now set up and ready to use the KVM testbed!
