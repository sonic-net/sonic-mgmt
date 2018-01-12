# Testbed Configuration

## Testbed Inventory

- [```ansible/lab```](../lab): Include all lab DUTs, fanout switches and testbed server topologies

- [```ansible/veos```](../veos): all servers and VMs

## Testbed Physical Topology

- [```ansible/files/sonic_lab_devices.csv```](../files/sonic_lab_devices.csv): Helper file helps you create lab_connection_graph.xml, list all devices that are physically connected to fanout testbed (all devices should be in ansible/lab)

- [```ansible/files/sonic_lab_links.csv```](../files/sonic_lab_links.csv): Helper file helps you to create lab_connection_graph.xml, list all physical links between DUT, Fanoutleaf and Fanout root switches, servers and vlan configurations for each link

- [```ansible/files/lab_connection_graph.xml```](../files/lab_connection_graph.xml): This is the lab graph file for library/conn_graph_facts.py to parse and get all lab fanout switch connections information. If you have only one fanout switch, you may go head manually modify the sample lab_connection_graph.xml file to set bot your fanout leaf and fanout root switch management IP point to the same fanout switch management IP and make sure all DUT and Fanout name and IP are matching your testbed.

- ```ansible/files/creategraph.py```: Helper file helps you generate a lab_connection_graph.xml based on the device file and link file specified above.

     Based on ansible_facts,  you may write ansible playbooks to deploy fanout switches or run test which requires to know the DUT physical connections to fanout switch


## Testbed Logical Topology

[```testbed.csv```](../testbed.csv) is the topology configuration file for the testbed.

### ```testbed.csv``` format
```
# conf-name,group-name,topo,ptf_image_name,ptf_mgmt_ip,server,vm_base,dut,comment
ptf1-m,ptf1,ptf32,docker-ptf-sai-mlnx,10.255.0.188/24,server_1,,str-msn2700-01,Tests ptf
vms-t1,vms1-1,t1,docker-ptf-sai-mlnx,10.255.0.178/24,server_1,VM0100,str-msn2700-01,Tests vms
vms-t1-lag,vms1-1,t1-lag,docker-ptf-sai-mlnx,10.255.0.178/24,server_1,VM0100,str-msn2700-01,Tests vms

```

- conf-name - to address row in table
- group-name – used in interface names, up to 8 characters
- topo – name of topology
- ptf_imagename – defines PTF image
- ptf_mgmt_ip – ip address for mgmt interface of PTF container
- server – server where the testbed resides
- vm_base – first VM for the testbed. If empty, no VMs are used
- dut – target dut name
- comment – any text here

### ```testbed.csv``` consistency rules
```
# uniq-name,testbed-name,topo,ptf_image_name,ptf_ip,server,vm_base,dut,owner
vms2-2-b,vms2-2,t1,docker-ptf-sai-brcm,10.0.10.7/23,server_1,VM0100,str-d6000-05,brcm test
vms2-2-m,vms2-2,t1,docker-ptf-sai-mlnx,10.0.10.7/23,server_1,VM0100,str-msn2700-5,mlnx test

```
Must be strictly checked in code reviews
 - uniq-name must be unique
 - All testbed records with the same testbed-name must have the same:
   - ptf_ip
   - server
   - vm_base
 - testbed-name must be up to 8 characters long
 - topo name must be valid (topo registered in ```veos``` and topo file presented in vars/topo_*.yml
 - ptf_imagename must be valid
 - server name must be valid and presented in veos inventory file
 - vm_base must not overlap with testbeds from different groups (different test-name)

TODO: check this constraints in testbed-cli.sh

## Generate and load SONiC configuration file

There is an ansible playbook `config_sonic_basedon_testbed.yml` which can help you generate a minigraph for your SONiC testbed based on the topology you specified and load the configuration minigraph.xml to SONiC DUT. 

When user call testbed-cli to deploy a testbed topology, use this playbook to generate matching SONiC minigraph file and deploy it into SONiC switch under test. 

Or when you know your topology name, you may use this playbook alone to generate a minigraph matching your topology name without deploy it.

VM Topologies are defined inside of vars/ directory in files vars/topo_{{ topology_name}}.yml

Every topology should have a name to distinct one topology from another on the server

Every topology contains a ptf container which will be used as placeholder for the injected interfaces from VMs, or direct connections to PTF host

VMs inventory file is also required to have all VMs ready for generating the minigraph file

VMs inventory is in file 'veos'

Template files for generating minigraph.xml are defined in template/topo directory

`TODO: Create xml graph template files for all available topologies; and create config_db style json configuration files to match all available topologies. No all checked in topologies have the correct xml graph template. T0, T1, T1-lag for 32 ports and t1-lag for 64 ports are supported for now.`

To generate and deploy minigraph for SONiC switch matching the VM topology please use following command:

`ansible-playbook -i lab config_sonic_basedon_testbed.yml -l sonic_dut_name -e vm_base=VM0300 -e topo=t0 [-e deploy=true]`

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
