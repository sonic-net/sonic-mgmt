# Sonic-Mgmt Testbed Setup
Setting up the sonic-mgmt testbed from Github to your own environment can be a tedious process. There are 10+ files that need to be updated before you can run test cases.

However, this process can be automated with the testbed.yaml file and TestbedProcessing.py script. The testbed.yaml file is a configuration file that compiles all the data needed to run the testcases into one file. TestbedProcess.py works by pulling information from that configuration file and pushing the data into the files where they belong. This guide will outline and facilitate the testbed set up of sonic-mgmt.


# Objective
The objective of this guide is to outline and facilitate the process of using the testbed.yaml and TestbedProcessing.py files. At the end of this guide, you should be able to setup the sonic-mgmt testbed and run the testcases.

Information for basic set up can be referenced at [Sonic-Mgmt Testbed Setup](/docs/testbed/README.testbed.Setup.md).


# Pre-migration Setup
There are several devices needed to get sonic-mgmt up and running with the test cases:
- Lab Server
- Root Fanout
- Leaf Fanout
- DUT (Device Under Test)

Information for testbed and topology can be referenced at [Sonic-Mgmt Testbed Overview](/docs/testbed/README.testbed.Overview.md)

# Modify Testbed.yaml Configuration File
There are 7 main sections in testbed.yaml that need to be edited:
1. device_groups
2. devices
3. host_vars
4. veos_groups
5. veos
6. testbed
7. topology

Each of the sections above contribute to the files that need to be written into in order for the test cases to run. For more information about what each file does, please reference [Sonic-Mgmt Testbed Configuration](/docs/testbed/README.testbed.Config.md).

Within the testbed.yaml file:

### (OPTIONAL) testbed_config section:
- name - choose a name for this testbed config file
- alias - choose an alias for this testbed config file

### device_groups section
**USAGE**: lab

The device_groups section generates the lab file which is the inventory file necessary for setting up the testbed. While the format in the configuration file is in yaml format, the script converts it to INI format. The device groups section includes all lab DUTs, fanout switches, and testbed server topologies. Group children are referenced from the devices section below. For the most part this section can be left alone.

### devices section
**USAGE**: files/sonic_lab_devices, group_vars/fanout/secrets, group_vars/lab/secrets, lab

The devices section is a dictionary that contains all devices and hosts. This section does not contain information on PTF containers. For more information on PTF containers, see the testbed.csv file.

For each device that you add, add the following:

| Hostname        | ansible_host | ansible_ssh_user | ansible_ssh_pass | HwSKU            | device_type |
| --------------- | ------------ | ---------------- | ---------------- | ---------------- | ----------- |
| str-msn2700-01  | [IP Address] | [username]       | [password]       | DevSonic         | DevSonic    |
| str-7260-10     | [IP Address] | [username]       | [password]       | Arista-7260QX-64 | FanoutRoot  |
| str-7260-10     | [IP Address] | [username]       | [password]       | Arista-7260QX-64 | FanoutLeaf  |
| str-acs-serv-01 | [IP Address] | [username]       | [password]       | TestServ         | Server      |

- hostname - names the devices you will use
- ansible_host - this is the managementIP where you can connect to to the device
- ansible_ssh_user - this is your username to login to the device
- ansible_ssh_pass - this is your password to login to the device
- hwsku - this is the look up value for credentials in /group_vars/all/labinfo.json. Without this section, things will fail. Make sure this field is filled out and verify labinfo.json is accurate.
- device type - the type of device. If you only have 4 devices, you can leave the provided labels alone

The lab server section requires different fields to be entered: ansible_become_pass, sonicadmin_user, sonicadmin_password, sonicadmin_initial_password. Sonicadmin_user is still just the username. The other fields is the password. These fields were selected because they are variables taken directly group_var/lab/secrets.yml. So for convenience, this section of the config file takes a copy of the variable labels.

### host_vars section:
**USAGE**: all host_var values

Define the host variables here. In this guide, we define the lab server (str-acs-serv-01) here.

For each host device that you add; define or verify the:
- mgmt_bridge
- mgmt_prefixlen (this should match with the mgmt_subnet_mask_length)
- mgmt_gw
- external_port

### veos_groups section:
**USAGE**: veos

The veos_group section is an inventory section for all servers and VMs. Although this section cross references the veos section, it differs from the veos section because the veos section contains information about the VMs that will be used in the testbed environment.

For the most part, the group names can be left alone. However, you should verify the:
- VM IDs - if the VM IDs are changed in the Veos section, you must reflect those changes here under your vms group(s).
- host/ lab server - if you have defined the lab server as something other than str-acs-serv-01, you must reflect the change in the host_var_file variable under server_1's vars subsection. You must also reflect the change in the host subsection of vm_host_1

Variables and values in this section may fluctuate greatly depending on your testbed environment.

### veos section:
**USAGE**: group_vars/eos/creds, main.yml, group_vars/vm_host/creds

Like the veos_groups section, this section contains information about the servers and VMs within your testbed. There are two sets of tasks to perform.

Confirm the following:
- root_path - server's root path to building the VMs
- cd_image_filename - you should be able to locate "Aboot-veos-serial-8.0.0.iso"
- hdd_image_file: you should also be able to locate "vEOS-lab-4.20.15M.vmdk"

Define:
- vm_console_base - if you are running multiple sets of sonic-mgmt VMs, define a conflict-free vm_console_base
- ansible_user - username to access VM
- ansible_password - password to access VM
- ansible_sudo_pass - same as password above
- vms_1
    - define the VMs that you want to bring up (i.e.: VM0200, VM0201, VM0202, etc...)
    - define the IPs of the VMs (i.e." 10.250.1.0, 10.250.1.1, 10.250.1.2, etc...)

### testbed section:
**USAGE**: testbed.csv

This is where the topology configuration file for the testbed will collect information from when running TestbedProcessing.py.

| #conf-name        | group-name         | topo    | ptf_image_name | ptf_ip       | server         | vm_base   | dut   | inv_name   | auto_recover   | comment   |
| ----------------- | ------------------ | ------- | -------------- | ------------ | -------------- | --------- | ----- | ---------- | -------------- | --------- |
| [ptf32 conf-name] | [ptf32 group-name] | [ptf32] | [docker-ptf]   | [ip address] | [server group] | [vm_base] | [dut] | [inv_name] | [auto_recover] | [comment] |
| [t0 conf-name]    | [t0 group-name]    | [t0]    | [docker-ptf]   | [ip address] | [server group] | [vm_base] | [dut] | [inv_name] | [auto_recover] | [comment] |


For each topology you use in your testbed environment, define the following:
- conf-name - to address row in table
- group-name - used in interface names, up to 8 characters. The variable can be anything but should be identifiable.
- topo - name of topology
- ptf_image_name - defines PTF image. In this guide, the docker-ptf was an image already on the local registry. However, there is a docker-ptf from the sonic-mgmt github that a user can pull from
    > git clone --recursive https://github.com/Azure/sonic-buildimage.git <br/>
    > make configure PLATFORM=generic <br/>
    > make target/docker-ptf.gz
- ptf_ip - ip address for mgmt interface of PTF container. Choose an IP address that is available
- server - server where the testbed resides. Choose a veos_group to use that contains both the lab server and virtual machines
- vm_base - enter in the lowest ID value for the VMs you will be using to run the test cases. The lowest VM ID value can be found under the veos section of the testbed configuration file. IF empty, no VMs are used
- dut - enter in the target DUT that is used in the testbed environment
- inv_name - inventory file name that contains the definition of the target DUTs
- auto_recover - (`yes`|`True`|`true`) to recover this testbed when runnings serve recovery script, (`no`|`False`|`false`) otherwise
- comment -  make a little note here
- ansible
    - ansible_host - IP address with port number
    - ansible_ssh_user - username to login to lab server
    - ansible_ssh_pass - password to login to lab server

### topology section:
**USAGE**: files/sonic_lab_links.csv

This section of the testbed configuration file defines the connection between the DUT to the leaf-fanout and the leaf-fanout to the lab server.

**Static Values**: the bandwidth remains at 100000. VlanMode from the DUT to the leaf-fanout is always "Access." However, VlanMode from the leaf-fanout to the lab server is "Trunk".

From the DUT to the leaf-fanout, make sure to define:
- end ports - which DUT port is connected to which leaf-fanout (end) port
- vlanIDs - this is very important because the VlanIDs will bind to the ports

From the leaf-fanout to the server, make sure to define:
- lab device - the testbed server you will be using (probably str-acs-serv-01)
- endport - find this in ifconfig on your testbed server
- vlanID (range) - if you have 32 ports, the range is from the lowest VlanID you defined +31, totaling 32 ports

### docker_registry section:
**USAGE**: /vars/docker_registry.yml

The docker registry container below information:

1. docker_registry_host

If you already have this information set up, you can choose to leave this section blank and the script will skip this section.

# Testbed Processing Script

When the testbed.yaml file is completed with the values pertaining to your setup, place both the TestbedProcess.py script and the testbed.yaml configuration file into sonic-mgmt/ansible.

Run the TestbedProcessing.py script:
> python TestbedProcessing.py -i testbed.yaml
>
> Options: <br/>
> -i = the testbed.yaml file to parse <br/>
> -basedir = the basedir for the project <br/>
> -backup = the backup directory for the files

### VMS Commands
Start VMS (using vms_1):
> ./testbed-cli.sh start-vms vms_1 password.txt

Stop VMS (using vms_1):
> ./testbed-cli.sh stop-vms vms_1 password.txt

### Deploy (PTF32) Topology Container
In this guide, ptf32-1 will be added using the testbed-cli.sh script as an example. However, other topologies can be added as well.

Remove topology ptf32-1:
> ./testbed-cli.sh remove-topo ptf32-1 password.txt

Add topology ptf32-1:
> ./testbed-cli.sh add-topo ptf32-1 password.txt

You can check to see if it was removed or added using the "docker ps" or "docker container ls" command.

### Running the First Test Case (Neighbour)
When VMs and ptf32-1 topology is successfully added, the first test case, “neighbour” can be run. The testbed name and test case name need to be exported first. Check to see if they were exported properly. Afterwards, the playbook can be run.

Run the following commands:
> export TESTBED_NAME=ptf32-1 <br/>
> export TESTCASE_NAME=neighbour <br/>
> echo $TESTBED_NAME <br/>
> echo $TESTCASE_NAME <br/>
> ansible-playbook -i lab -l sonic-ag9032 test_sonic.yml -e testbed_name=$TESTBED_NAME -e testcase_name=$TESTCASE_NAME


# Troubleshooting
Issue: Testbed Command Line complains there is no password file available. <br/>
Resolution: You can bypass this issue by creating an empty password file. CLI should be able to run afterwards.

Issue: The IPs I want to use are unavailable even after running the stop-vms command. <br />
Resolution: If you ran the stop-vms command and still face this issue, you can run the following:
> virsh <br/>
> list <br/>
> destroy VM_Name (delete the VM that is occupying the IP) <br/>
> exit (exit out of virsh)
However, make sure that no one else is using those IPs before permanently deleting the IPs


Issue: Task setup failure. SSH Error: data could not be sent to the remote host <br/>
Resolution: There are a plethora of things that could be wrong here. Here are some potential issues:
1. Make sure this host can be reached over SSH
2. Does your group_vars/all/lab_info.json file contain the correct credentials?
3. Does your device have the correct hwsku in files/sonic_lab_devices.csv?
4. Confirm that your lab file does not have "/"s after the IPs. "/"s are a way to denote port numbers which INI files do not recognize.
5. Recheck your testbed.yaml configuration file to see if you got the IPs and credentials correct
