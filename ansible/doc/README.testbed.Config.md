# Testbed Configuration

```testbed.csv``` is the topology configuration file for the testbed.

# ```testbed.csv```
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

# ```testbed.csv``` consistency rules
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
