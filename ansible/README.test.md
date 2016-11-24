# ansible playbooks for SONiC testing

## Requirements
- A testbed needed to be set up before hand. See [Testbed](README.testbed.md) for more information.
 -- Depending on the test, either a PTF testbed or a VM set testbed might be required. 

## Run Tests
- Replace {DUT_NAME} in each command line with the host name of switch under test.

### NTP Test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags ntp
```

### Syslog Test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags syslog
```

### SNMP Tests
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} --become --tags snmp,snmp_cpu,snmp_interfaces
```

### LLDP Test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME},lldp_neighbors --become --tags lldp
```
- Required switch connected to a VM set testbed.
