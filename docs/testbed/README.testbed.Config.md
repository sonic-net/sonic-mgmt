# Testbed Configuration

## Testbed Inventory

- [```ansible/lab```](/ansible/lab): Include all lab DUTs, fanout switches and testbed server topologies

- [```ansible/veos```](/ansible/veos): all servers and VMs

## Testbed Physical Topology

- [```ansible/files/sonic_lab_devices.csv```](/ansible/files/sonic_lab_devices.csv): Helper file helps you create lab_connection_graph.xml, list all devices that are physically connected to fanout testbed (all devices should be in ansible/lab)

- [```ansible/files/sonic_lab_links.csv```](/ansible/files/sonic_lab_links.csv): Helper file helps you to create lab_connection_graph.xml, list all physical links between DUT, Fanoutleaf and Fanout root switches, servers and vlan configurations for each link

- [```ansible/files/lab_connection_graph.xml```](/ansible/files/lab_connection_graph.xml): This is the lab graph file for library/conn_graph_facts.py to parse and get all lab fanout switch connections information. If you have only one fanout switch, you may go head manually modify the sample lab_connection_graph.xml file to set bot your fanout leaf and fanout root switch management IP point to the same fanout switch management IP and make sure all DUT and Fanout name and IP are matching your testbed.

- [```ansible/files/creategraph.py```](/ansible/files/creategraph.py): Helper file helps you generate a lab_connection_graph.xml based on the device file and link file specified above.

     Based on ansible_facts,  you may write ansible playbooks to deploy fanout switches or run test which requires to know the DUT physical connections to fanout switch


## Testbed Logical Topology

[```testbed.csv```](/ansible/testbed.csv) is the topology configuration file for the testbed.

### ```testbed.csv``` format
```
# conf-name,group-name,topo,ptf_image_name,ptf,ptf_ip,ptf_ipv6,server,vm_base,dut,inv_name,auto_recover,comment
ptf1-m,ptf1,ptf32,docker-ptf,ptf-1,10.255.0.188/24,,server_1,,str-msn2700-01,lab,False,Tests ptf
vms-t1,vms1-1,t1,docker-ptf,ptf-2,10.255.0.178/24,,server_1,VM0100,str-msn2700-01,lab,True,Tests vms
vms-t1-lag,vms1-1,t1-lag,docker-ptf,ptf-3,10.255.0.178/24,,server_1,VM0100,str-msn2700-01,lab,True,Tests vms

```

- conf-name - to address row in table
- group-name – used in interface names, up to 8 characters
- topo – name of topology
- ptf_imagename – defines PTF image
- ptf_ip – ip address for mgmt interface of PTF container
- server – server where the testbed resides
- vm_base – first VM for the testbed. If empty, no VMs are used
- dut – target dut name
- inv_name - inventory file name that contains the definition of the target DUTs
- auto_recover - (`yes`|`True`|`true`) to recover this testbed when runnings serve recovery script, (`no`|`False`|`false`) otherwise
- comment – any text here

### ```testbed.csv``` consistency rules
```
# conf-name,group-name,topo,ptf_image_name,ptf,ptf_ip,ptf_ipv6,server,vm_base,dut,comment
vms2-2-b,vms2-2,t1,docker-ptf,ptf-1,10.0.10.7/23,,server_1,VM0100,str-d6000-05,brcm test
vms2-2-m,vms2-2,t1,docker-ptf,ptf-2,10.0.10.7/23,,server_1,VM0100,str-msn2700-5,mlnx test

```
Must be strictly checked in code reviews
 - conf-name must be unique
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


