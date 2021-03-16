# Testbed Setup with Keysight IxANVL container and SONIC Virtual DUT
 
 This document describes the steps to setup a testbed with Keysight IxANVL container and SONIC Virtual DUT to run BGP conformance test cases. 
 
 ### Testbed server 
 The schematic diagram below provides an overview of the setup. 
 ![](img\keysight_ixanvl_testbed_topology.png) 
 
 ### Network connections 
 - The testbed server has 1 network port: 
   - A management port to manage the server, IxANVL container, sonic-mgmt container running on the server. 
 
 ### Prepare testbed server 
 
 - If the testbed host is a VM, then it must support nested virtualization
   - [Instructions for Hyper-V based VMs](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization#configure-nested-virtualization)
 - Python version should be atleast `2.7.17`. 
 - Install docker as below. The docker here is needed to run the sonic-mgmt container. 

     ```shell 
     $ wget -O get-docker.sh https://get.docker.com/ 
  
     $ sudo ./get-docker.sh 
     ``` 
 - [Install Docker CE](https://docs.docker.com/install/linux/docker-ce/ubuntu/). 
 - Be sure to follow the [post-install instructions](https://docs.docker.com/install/linux/linux-postinstall/) so that you don't need sudo privileges to run docker commands.
 - Run the host setup script to install required packages and initialize the management bridge network

     ```
     git clone https://github.com/Azure/sonic-mgmt
     cd sonic-mgmt/ansible
     sudo ./setup-management-network.sh
     ```

     **NOTE** setup-management-network.sh can fail on a check of br1 exists or not. In that case you can modify the script and comment out if checks of line 45 and line 49 until the issue is fixed.

   This step creates a bridge interface called 'br1' in your host. It is the management bridge of the topology that is to be deployed. 
   To access outside networks other than management network run the below script. The access to the outside network may be needed in case any host outside the testbed is used to activate the licenses needed to run IxANVL. That host will then become the License Server for the IxANVL application.

     ```
     cd sonic-mgmt/ansible
     sudo ./setup-br1-nat.sh <external-iface-host> (external-iface-host can be any interface which connects to other networks. Mostly this is the LAN interface of the host.)
	 ```
 
  - Download Keysight IxANVL container image from the below location
    - [IxANVL](https://downloads.ixiacom.com/support/downloads_and_updates/eb/1558879/anvl_docker_image.tar). The path is not of ixia webserver as IxANVL container is not released yet. Once released the path will be properly updated. 
 
     Downloaded files would be like below - 
     - `anvl_docker_image.tar` 
 
   - Place the downloaded file in a folder say `~/keysight_images`.
     Setup a local docker registry for IxANVL container image.  
     > **Note** If you load the *IxANVL* docker image in your docker registry then you need not place `anvl_container.tar` inside the `~/keysight_images` folder. In that case you need to consider the `docker_registry_host` in `ansible/vars/docker_registry.yml` file. If local file is used it will not pull from the docker registry. 
     > **Note** For setting up local docker registry please follow the instructions from the link: (https://docs.docker.com/registry/deploying/)
     To setup local docker registry in docker host below are the commands that need to be run:

	```
	$ docker image load < anvl_docker_image.tar
	$ docker run -d -p 5000:5000 --restart=always --name registry registry:2
	$ docker tag anvl_container:latest localhost:5000/docker-ptf-anvl
	$ docker push localhost:5000/docker-ptf-anvl

	```
     docker-ptf-anvl is the ptf-imagename in testbed.csv in sonic-mgmt/ansible

  - Download the sonic-vs image
	To run the tests with a virtual SONiC device, we need a virtual SONiC image. The simplest way to do so is to download a public build from Jenkins.

	- Download the sonic-vs image from [here](https://sonic-jenkins.westus2.cloudapp.azure.com/job/vs/job/buildimage-vs-image/lastSuccessfulBuild/artifact/target/sonic-vs.img.gz)

	```
	$ wget https://sonic-jenkins.westus2.cloudapp.azure.com/job/vs/job/buildimage-vs-image/lastSuccessfulBuild/artifact/target/sonic-vs.img.gz
	```

        - Unzip the image and move it into `~/sonic-vm/images/`

	```
	$ gzip -d sonic-vs.img.gz
	$ mkdir -p ~/sonic-vm/images
	$ mv sonic-vs.img ~/sonic-vm/images
	```
   - Setup sonic-mgmt docker
	All testbed configuration steps and tests are run from a `sonic-mgmt` docker container. This container has all the necessary packages and tools for SONiC testing so that test behavior is consistent between different developers and lab setups.

	Run the `setup-container.sh` in the root directory of the sonic-mgmt repository:

	```
	$ cd sonic-mgmt
	$ ./setup-container.sh -n <container name> -d /data
	```

	From now on, **all steps are running inside the sonic-mgmt docker**, unless otherwise specified.


	You can enter your sonic-mgmt container with the following command:

	```
	$ docker exec -it <container name> bash
	```

	You will find your sonic-mgmt directory mounted at `/data/sonic-mgmt`:

	```
	$ ls /data/sonic-mgmt/
	LICENSE  README.md  __pycache__  ansible  docs	lgtm.yml  setup-container.sh  spytest  test_reporting  tests
	```

   - Setup host public key in sonic-mgmt docker
	In order to configure the testbed on your host automatically, Ansible needs to be able to SSH into it without a password prompt. The `setup-container` script from the previous step will setup all the necessary SSH keys for you, but there are a few more modifications needed to make Ansible work:

	Modify `veos_vtb` to use the user name and password (e.g. `foo`) you want to use to login to the host machine (this can be your username on the host)

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
	+      ansible_password: foo

 	vms_1:
   	hosts:
	```

	Create a dummy `password.txt` file under `/data/sonic-mgmt/ansible`
    	- **Note**: Here, `password.txt` is the Ansible Vault password file. Ansible allows users to use Ansible Vault to encrypt password files.

      	By default, the testbed scripts require a password file. If you are not using Ansible Vault, you can create a file with a dummy password (e.g. `abc`) and pass the filename to the command line. The file name and location is created and maintained by the user.

	**On the host,** after doing ssh from sonic-mgmt container, run `sudo visudo` and add the following line at the end:

	```
	foo ALL=(ALL) NOPASSWD:ALL
	```

	Verify that you can login into the host (e.g. `ssh foo@172.17.0.1`) from the `sonic-mgmt` container without any password prompt.

	Verify that you can use `sudo` without a password prompt inside the host (e.g. `sudo bash`).

   - Deploy PTF32 topology
	Now we're finally ready to deploy the topology for our testbed! Run the following command:

	```
	$ cd /data/sonic-mgmt/ansible
	$ ./testbed-cli.sh -t testbed.csv -m veos_vtb add-topo ixanvl-vs-conf password.txt
	```
   - Verify that you can login to the SONiC KVM using Mgmt IP = 10.250.0.101 and admin:password.
  
 ### Run a Pytest
 	Now that the testbed has been fully setup and configured, let's run a simple test to make sure everything is functioning as expected.

	- Switch over to the `tests` directory:

	```
	cd sonic-mgmt/tests
	```

	- Run the following command to execute the `bgp_fact` test (including the pre/post setup steps):

	```
	./run_tests.sh -n ixanvl-vs-conf -d vlab01 -c ixia/ixanvl/test_anvl_run.py -f ../ansible/testbed.csv -i veos_vtb
	```

	You should see 1 set of tests run and pass. You're now set up and ready to use the IxANVL testbed!
