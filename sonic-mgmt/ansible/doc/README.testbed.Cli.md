# Testbed Command Line

```testbed-cli.sh``` is the command line to setup/teardown the testbed, as well as add/remove/switch topology.

- Maintenance purposes only
  - ```./testbed-cli.sh start-vms {server_name} ~./password```   # after a server restarted
  - ```./testbed-cli.sh stop-vms {server_name} ~./password```    # before a server restarted
- General usage
  - ```./testbed-cli.sh add-topo {topo_name} ~./password```      # create topo with name {topo_name} from testbed.csv
  - ```./testbed-cli.sh remove-topo {topo_name} ~./password```   # destroy topo with name {topo_name} from testbed.csv
  - ```./testbed-cli.sh renumber-topo {topo_name} ~./password``` # renumber topo with name {topo_name} from testbed.csv

## Add/Remove topo
```
# conf-name,testbed-name,topo,ptf_image_name,ptf_ip,server,vm_base,dut,owner
vms1-1-t1,vms1-1,t1,docker-ptf-sai-mlnx,10.0.10.5/23,server_1,VM0100,str-msn2700-11,t1 tests
vms1-1-t1-lag,vms1-1,t1-lag,docker-ptf-sai-mlnx,10.0.10.5/23,server_1,VM0100,str-msn2700-11,t1-lag tests

```
Goal is to use one VM with different topologies

- To add a new testbed “vms1-1-t1”:
  - ./testbed-cli add-topo vms1-1-t1 ~/.password

- To switch from testbed “vms1-1-t1” to testbed “vms1-1-lag”
  - ./testbed-cli remove-topo vms1-1-t1 ~/.password
  - ./testbed-cli add-topo vms1-1-t1-lag ~/.password

Feature: The VMs configuration will be updated while switching from one topo to another
Feature: Might be used for renumbering too
Caveat: Have to remember what was the initial topology. Should be fixed in future

# Renumber topo
```
# conf-name,testbed-name,topo,ptf_image_name,ptf_ip,server,vm_base,dut,owner
vms2-2-b,vms2-2,t1,docker-ptf-sai-brcm,10.0.10.7/23,server_1,VM0100,str-d6000-05,brcm test
vms2-2-m,vms2-2,t1,docker-ptf-sai-mlnx,10.0.10.7/23,server_1,VM0100,str-msn2700-5,mlnx test

```
Goal is to use one VM set against different DUTs

- To add a new testbed “vms2-2-b”:
  - ./testbed-cli add-topo vms2-2-b ~/.password

- To switch from testbed “vms2-2-b” to testbed “vms2-2-m”
  - ./testbed-cli renumber-topo vms2-2-m ~/.password

Feature: The VMs configuration will NOT be updated while switching from one topo to another (faster).

TODO: check topo field when renumbering between topologies
