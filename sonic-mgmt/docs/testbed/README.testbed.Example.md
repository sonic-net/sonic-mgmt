
# **EXAMPLE OF DEPLOY TESTBED AND RUN TEST CASES**

Here is a quick walk through of how to bring up and connect your testbed and SONiC DUT to run test cases
Please make sure you have following ready:

  - You have your fanout switch ready, reachable and all physical cable are connected correct
  - You have your test server ready and reachable
  - You have your SONiC DUT readd, reachable and loaded with SONiC image
  - You have your lab graph file edited/created matching your testbed configuraton and connection.
  - You have successfully started your sonic-mgmt docker and be able to login to docker and run ansible-playbook.

## **Deploy your testbed VMs and topology**

  - Make sure you have started all VMs on your testserver
  - Make sure you edited `ansible/veos` server inventory file that reflect your servers and VMs assignment
  - Make sure you edited your lab inventory `ansible/inventory` or `ansible/lab` file to include all DUTs and fanout switches
  - Make sure your lab graph file `ansible/files/lab_connection_graph.xml` reflects your lab physical and logical setup

### Define your testbed

Edit your `ansible/testbed.csv' file to have following line:
  `user1-t0,vms1-1,t0,docker-ptf,10.255.0.79/24,server_1,VM0100,user_sonic_dut,user1`
  Here user defined:
  - name the topology as `user1-to`, this is the keyword that user use to identify this topology
  - name the internal name as `vms1-1` which will be used internally in server for this topology
  - specify the deployed topology as `t0`
  - specify the ptf docker container type associated with this topology
  - specify the ptf docker container management IP as `10.255.0.79/24`
  - specify the server name as `server_1` which match the server name defined in `ansible/veos`
  - identify the starting VM number for this topology (Here the starting VM is 100, since it's a t0 topology, it will consume 100,101,102 and 103 total 4 VMs from your VM inventory, make sure all those VMs are available)
  - SONiC DUT name `user_sonic_dut` that user want to connect to this testbed (needs consistent with inventory file)
  - the last column is the comment field which you may put any note your want.

Run following command to deploy your topology(password_file is the filename for Ansible Vault password file, if you are not using Vault to encrpt, just give here a blank file):
`testbed-cli.sh add-topo user1-t0 password_file`

### Deploy your defined testbed

Run following command to deploy your topology(password_file is the filename for Ansible Vault password file, if you are not using Vault to encrpt, just give here a blank file):
`testbed-cli.sh add-topo user1-t0 password_file`


## **Create minigraph.xml for SONiC**

Based on the topology you created, you may run a playbook to generate a minigraph.xml for your SONiC DUT to match your newly deployed topology. When you call testbed-cli to deploy a testbed topology from above step, use this playbook to generate matching SONiC minigraph file and deploy it into SONiC switch

To generate and deploy minigraph for SONiC switch matching the VM topology please use following command:

`ansible-playbook -i lab config_sonic_basedon_testbed.yml -l sonic_dut_name -e vm_base=VM0300 -e topo=t0 [-e deploy=true -e save=true]`

```Parameters
-l str-msn2700-01          - the sonic_dut_name you are going to generate minigraph for
-e vm_base=VM0300          - the VM name which is used to as base to calculate VM name for this set
-e topo=t0                 - the name of topology to generate minigraph file
-e deploy=True             - if deploy the newly generated minigraph to the targent DUT, default is false if not defined
-e save=True               - if save the newly generated minigraph to the targent DUT as starup-config, default is false if not defined
```

After minigraph.xml is generated, the playbook will replace the original minigraph file under ansible/minigraph/ with the newly generated minigraph file for the SONiC device.

The playbook will based on deploy=True or False to deside if load the SONiC device with new minigraph or not.
```
If deploy=true, the playbook will apply the newly generated minigraph to the SONiC switch
If save=true, the playbook will save the newly generated minigraph to SONiC switch as startup-config
```
## **Run tests**

Run test from sonic-mgmt docker to avoid incompatibility issue. This is going to be the supported method to call individual test case going forward. All test cases name and calling variables and applied topologies are specified in ansible/roles/test/vars/testcases.yml

When calling test, testbed_name is the main entry to pickup/understand the testbed information associated with the test (ie. ptf_host and tyestbed_type, VMs info...). testbed_name is inherited from your own `ansible/testbed.csv` file.  The first column of each line(one testbed topology definition) is the unique name of the testbed and will be used in testbed_name option when calling test.

***Example of running a test case:***
    `ansible-playbook -i lab -l str-sonic-1 test_sonic.yml -e testbed_name={TESTBED_NAME} -e testcase_name={TESTCASE_NAME}`

Where:
```
    `testcase_name=bgp_fact`
    `testbed_name=vms-t1-lag`
```

Deprecating way to call test could be find [here](/docs/ansible/README.test.md)
