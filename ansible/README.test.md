# Ansible Playbooks for Testing SONiC

## Requirements
- A testbed needed to be set up before hand. See [Testbed](README.testbed.md) for more information.
 -- Depending on the test, either a PTF testbed or a VM set testbed might be required. 

## How to Run Tests
- Replace {DUT_NAME} in each command line with the host name of switch under test
- Replace {PTF_HOST} in each command line with the host name or IP of the PTF testbed host
- Replace {TESTBED_TYPE} in each command line with the type of the testbed being used

### ACL tests
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags acl   --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST}"
```
- Requires switch connected to a t1 or t1-lag testbed

### ARP tests
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags arp --extra-vars "ptf_host={PTF_HOST}"
```
- Requires switch connected to a PTF testbed

### BGP facts verification test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags bgp_fact
```
- Requires switch connected to a VM set testbed

### CoPP test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags copp --extra-vars "ptf_host={PTF_HOST}"
```
- Requires switch connected to a PTF testbed

### DHCP relay test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags dhcp_relay --extra-vars "ptf_host={PTF_HOST}"
```
- Requires switch connected to a PTF testbed

### Everflow_testbed test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags everflow_testbed --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST}"
```
- Requires switch connected to a VM testbed

### FDB test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags fdb --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST} [ipv6=True]"
```
- Requires switch connected to a VM testbed(t0); default IPv4

### FIB test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags fib --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST} [ipv4=Flase]"
```
- Requires switch connected to a VM testbed; default IPv4

### MTU test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags mtu --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST}"
```
- Requires switch connected to a t1 or t1-lag testbed

### Fast-Reboot test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags fast_reboot --extra-vars "ptf_host={PTF_HOST}"
```
- Requires switch connected to a PTF testbed

### IPDecap Test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} -tags decap --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST} dscp_mode=pipe|uniform"
```
- Require VM testbed
- dscp_mode=pipe: if your ASIC type is Broadcom; 
- dscp_mode=uniform: if your ASIC type is Mellanox

### Lag-2 test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags lag-2 --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST}"
```
- Requires switch connected to a VM testbed with lag configured (t0, t1-lag)

### LLDP test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME},lldp_neighbors --become --tags lldp
```
- Requires switch connected to a VM set testbed

### Link flap test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME}, --become --tags link_flap
```
- Requires switch connected to fanout switch. VM or PTF testbed

### NTP test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags ntp
```

### SNMP tests
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags snmp,snmp_cpu,snmp_interfaces
```
- Require to run Anisble-playbook from docker-sonic-mgmt container. 

### Sensors test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags sensors
```

### Syslog test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags syslog
```

### PFC WD test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags pfc_wd --extra-vars "testbed_type={TESTBED_TYPE}"
```
PFC WD test assumes that Fanout switch has [PFC generator](https://github.com/marian-pritsak/pfctest/blob/master/pfctest.py) available.
