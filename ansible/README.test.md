 # **Ansible Playbooks for Testing SONiC**

## **Requirements**
- A testbed needed to be set up before hand. See [Testbed](README.testbed.md) for more information.
- Depending on the test, either a PTF testbed or a VM set testbed might be required. 
- All management IP addresses, VM, ptf docker, SONiC, fanout switches, servers should be routable/reachable in testbed.
- Syslog test: the run this test, sonic-mgmt docker needs to be started with host=net 

---

## **How to Run Tests**

### **Run test by test case name**

This is going to be the supported method to call individual test case going forward. All test cases name and calling variables and applied topologies are specified in [ansible/roles/test/vars/testcases.yml](roles/test/vars/testcases.yml)

When calling test, testbed_name is the main entry to pickup/understand the testbed information associated with the test (ie. ptf_host and tyestbed_type, VMs info...). testbed_name is inherited from your own `ansible/testbed.csv` file.  The first column of each line(one testbed topology definition) is the unique name of the testbed and will be used in testbed_name option when calling test.

***Example of running a test case:*** 
    `ansible-playbook -i lab -l str-s6000-acs-1 test_sonic.yml -e testbed_name={TESTBED_NAME} -e testcase_name={TESTCASE_NAME}` 

Where:

		`testcase_name=bgp_fact`
		`testbed_name=vms-t1-lag`

---
### **Run test by test case tag `(DEPRECATING)`**

When Ansible running playbooks by tag, it first include all tasks(all test cases) within test role shich not relate to specific tag. It's very slow along with adding more test cases and it occupied too much resource other than just run one test case using specific tag. It does not scale. 

We newly added a run test case by test name option(see above setion). Running test by tag option won’t be actively maintained going forward, but will backward compatible for all already working test cases, and eventually will be phaseout. There still going to be more improvement after the initial check in. 

- Replace {DUT_NAME} in each command line with the host name of switch under test
- Replace {PTF_HOST} in each command line with the host name or IP of the PTF testbed host
- Replace {TESTBED_TYPE} in each command line with the type of the testbed being used

##### ACL tests
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags acl   --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST}"
```
- Requires switch connected to a t1 or t1-lag testbed

##### ARP tests
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags arp --extra-vars "ptf_host={PTF_HOST}"
```
- Requires switch connected to a PTF testbed

##### BGP facts verification test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags bgp_fact
```
- Requires switch connected to a VM set testbed

##### CoPP test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags copp --extra-vars "ptf_host={PTF_HOST}"
```
- Requires switch connected to a PTF testbed

##### DHCP relay test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags dhcp_relay --extra-vars "ptf_host={PTF_HOST}"
```
- Requires switch connected to a PTF testbed

##### ECN WRED test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags ecn_wred
```
- Requires switch connected to a VM testbed

##### Everflow_testbed test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags everflow_testbed --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST}"
```
- Requires switch connected to a VM testbed

##### FDB test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags fdb --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST} [ipv6=True]"
```
- Requires switch connected to a VM testbed(t0); default IPv4

##### FIB test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags fib --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST} [ipv4=Flase]"
```
- Requires switch connected to a VM testbed; default IPv4

##### MTU test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags mtu --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST}"
```
- Requires switch connected to a t1 or t1-lag testbed

##### Fast-Reboot test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags fast_reboot --extra-vars "ptf_host={PTF_HOST}"
```
- Requires switch connected to a PTF testbed

##### IPDecap Test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} -tags decap --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST} dscp_mode=pipe|uniform"
```
- Require VM testbed
- dscp_mode=pipe: if your ASIC type is Broadcom; 
- dscp_mode=uniform: if your ASIC type is Mellanox

##### Lag-2 test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags lag-2 --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST}"
```
- Requires switch connected to a VM testbed with lag configured (t0, t1-lag)

##### LLDP test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME},lldp_neighbors --become --tags lldp
```
- Requires switch connected to a VM set testbed

##### Link flap test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME}, --become --tags link_flap
```
- Requires switch connected to fanout switch. VM or PTF testbed

##### NTP test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags ntp
```

##### SNMP tests
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags snmp,snmp_cpu,snmp_interfaces
```
- Require to run Anisble-playbook from docker-sonic-mgmt container. 

##### Sensors test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags sensors
```

##### Syslog test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags syslog
```

##### PFC WD test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags pfc_wd --extra-vars "testbed_type={TESTBED_TYPE}"
```

##### BGP multipath relax test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags bgp_multipath_relax --extra-vars "testbed_type={TESTBED_TYPE}"
```
This test only works for T1 related topologies(t1, t1-lag, ...) 
You might need to redeploy your VMs before you run this test due to the change for ToR VM router configuration changes
`./testbed-cli.sh config-vm your-topo-name(vms1-1) your-vm-name(VM0108)` will do this for you

##### VLAN test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} -e "testbed_name={TESTBED_NAME} testcase_name=vlan"
```
- Requires switch connected to a t0 testbed
- Requires switch connected to fanout switch and fanout switch need support [QinQ](https://en.wikipedia.org/wiki/IEEE_802.1ad).

### CRM test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags crm
