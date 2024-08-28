# SONiC testbed management infrastructure
* The SONiC testbed consists of multiple interrelated configuration files that are difficult and error-prone edit manually.
* They are not frequently modified and only handful of persons like owners/admin has authority to modify them. But creating the initial setup or retrieving a broken setup is more challenging task for them.
* User scripts runs inside the docker container loads and access these files, and if the container is corrupted or crashed these files will be lost and will be difficult to get back easily. This will be challenging time for the user who doesn’t have the knowledge of interrelationship of the files.
# So how do we onboard engineer to write tests?
* Keep the testbed files in the separate repository outside the SONiC docker image.
* Provision the engineers to keep the code in their local machine and mount them while loading the docker container. So, code will be in the local directory and won’t get lost if the container is wrecked.
* Give the engineer a script to build the testbed from the stored files in the repository.

# Workflows
Before going to the work flows please look into the [basic docker commands to create the sonic-mgmt environment](DockerCommands.md).
Also before getting invloved into any of the workflow1 or workflow2 please make sure that you have loaded the sonic docker image to be executed using locker load command.
```sudo docker load -i docker-sonic-mgmt```
### workflow1
* Fork the sonic-mgmt(https://github.com/Azure/sonic-mgmt.git) repo.
  * <i>Make sure you clone the forked version from your repo</i>
      - Ex: git clone https://github.com/sonic-net/sonic-mgmt
* load the docker image such that it mounts sonic-mgmt inside the container.
    * <i> Make sure the path is matching the criteria</i>
  * sudo docker run -it --name sonic --privileged -v /home/ubuntu/sonic-mgmt/:/var/johnar/sonic-mgmt  --user johnar:gjohnar docker-sonic-mgmt
* Install Snappi packages
    * python -m pip install --upgrade "snappi==0.9.1"
    * python -m pip install --upgrade "snappi[convergence]==0.4.1"
    * python -m pip install --upgrade "snappi[ixnetwork]==0.9.1"
* Mention the topology details in the following files
    - ansible/files/graph_groups.yml
    - ansible/files/sonic_snappi-sonic_devices.csv
    - ansible/files/sonic_snappi-sonic_links.csv
    - ansible/group_vars/snappi-sonic/secrets.yml
    - ansible/group_vars/snappi-sonic/snappi-sonic.yml
    - ansible/snappi-sonic
    - ansible/testbed.csv
* Run the test
  * cd ~/sonic-mgmt/tests/
  * Add environment variables
    * export ANSIBLE_CONFIG=../ansible
    * export ANSIBLE_LIBRARY=../ansible
  * Run Single-Dut case
    * py.test --inventory ../ansible/snappi-sonic --host-pattern sonic-s6100-dut1 --testbed vms-snappi-sonic --testbed_file ../ansible/testbed.csv --show-capture=stdout --log-cli-level info --showlocals -ra --allow_recover --skip_sanity --disable_loganalyzer test_pretest.py
  * Run Multi-Dut case
    * py.test --inventory ../ansible/snappi-sonic --host-pattern all --testbed vms-snappi-sonic-multidut --testbed_file ../ansible/testbed.csv --show-capture=stdout --log-cli-level info --showlocals -ra --allow_recover --skip_sanity --disable_loganalyzer test_pretest.py
 * In this workflow your test script or code will remain intact even if docker image is destroyed unintentionally since you are actually keeping the code in the (mounted) local directory.

### workflow2
* Simply load the docker image no mounts of local folders are required.
  * sudo docker run -it --name sonic docker-sonic-mgmt
* Inside the container clone the forked version of sonic-mgmt(https://github.com/Azure/sonic-mgmt.git)
    - Ex: git clone https://github.com/sonic-net/sonic-mgmt
* Install Snappi packages
    * python -m pip install --upgrade "snappi==0.9.1"
    * python -m pip install --upgrade "snappi[convergence]==0.4.1"
    * python -m pip install --upgrade "snappi[ixnetwork]==0.9.1"
* Mention the topology details in the following files (create the files if not present already)
    - ansible/files/graph_groups.yml
    - ansible/files/sonic_snappi-sonic_devices.csv
    - ansible/files/sonic_snappi-sonic_links.csv
    - ansible/group_vars/snappi-sonic/secrets.yml
    - ansible/group_vars/snappi-sonic/snappi-sonic.yml
    - ansible/snappi-sonic
    - ansible/testbed.csv
* Run the test
  * cd ~/sonic-mgmt/tests/
  * Add environment variables
    * export ANSIBLE_CONFIG=../ansible
    * export ANSIBLE_LIBRARY=../ansible
  * Run Single-Dut case
    * py.test --inventory ../ansible/snappi-sonic --host-pattern sonic-s6100-dut1 --testbed vms-snappi-sonic --testbed_file ../ansible/testbed.csv --show-capture=stdout --log-cli-level info --showlocals -ra --allow_recover --skip_sanity --disable_loganalyzer test_pretest.py
  * Run Multi-Dut case
    * py.test --inventory ../ansible/snappi-sonic --host-pattern all --testbed vms-snappi-sonic-multidut --testbed_file ../ansible/testbed.csv --show-capture=stdout --log-cli-level info --showlocals -ra --allow_recover --skip_sanity --disable_loganalyzer test_pretest.py
* In this workflow if you make certain local change inside the folder ~/sonic-mgmt/ that will not be saved if the container got corrupted somehow.
