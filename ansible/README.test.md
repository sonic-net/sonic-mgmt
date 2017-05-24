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
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags acltb_configure --extra-vars "run_dir=/tmp testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST}"
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags acltb_test      --extra-vars "run_dir=/tmp testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST}"
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags acltb_cleanup   --extra-vars "run_dir=/tmp testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST}"
```
- Requires switch connected to a PTF testbed

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

### FIB test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --tags fib --extra-vars "testbed_type={TESTBED_TYPE} ptf_host={PTF_HOST}"
```
- Requires switch connected to a PTF testbed

### Fast-Reboot test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags fast_reboot --extra-vars "ptf_host={PTF_HOST}"
```
- Requires switch connected to a PTF testbed

### LLDP test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME},lldp_neighbors --become --tags lldp
```
- Requires switch connected to a VM set testbed

### Link flap test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME}, --become --tags link_flap
```
- Requires switch connected to a VM set testbed

### NTP test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags ntp
```

### SNMP tests
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags snmp,snmp_cpu,snmp_interfaces
```

### Sensors test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags sensors
```

### Syslog test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags syslog
```

