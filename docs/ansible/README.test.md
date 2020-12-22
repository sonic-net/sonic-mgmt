 # **Ansible Playbooks for Testing SONiC**

## **Requirements**
- A testbed needed to be set up before hand. See [Testbed](/docs/testbed/README.md) for more information.
- Depending on the test, either a PTF testbed or a VM set testbed might be required.
- All management IP addresses, VM, ptf docker, SONiC, fanout switches, servers should be routable/reachable in testbed.
- Syslog test: the run this test, sonic-mgmt docker needs to be started with host=net

---

## **How to Run Tests**

### **Run test by test case name**

All test cases name and calling variables and applied topologies are specified in [ansible/roles/test/vars/testcases.yml](/ansible/roles/test/vars/testcases.yml)

When calling test, testbed_name is the main entry to pickup/understand the testbed information associated with the test (ie. ptf_host and testbed_type, VMs info...). testbed_name is inherited from your own `ansible/testbed.csv` file.  The first column of each line(one testbed topology definition) is the unique name of the testbed and will be used in testbed_name option when calling test.

***Example of running a test case:***
    `ansible-playbook -i {INVENTORY} -l {DUT_NAME} test_sonic.yml -e testbed_name={TESTBED_NAME} -e testcase_name={TESTCASE_NAME}`

Where:

		`testcase_name=bgp_fact`
		`testbed_name=vms-t1-lag`

- Replace {INVENTORY} in each command line with the inventory file name
- Replace {DUT_NAME} in each command line with the host name of switch under test
- Replace {TESTBED_NAME} in each command line with the first column in your 'ansible/testbed.csv' file associated with the DUT_NAME
- Replace {TESTCASE_NAME} in each command line with the testcase tag from 'roles/test/vars/testcases.yml'
---

##### ACL tests
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=acl -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set testbed

##### ARP tests
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=arp -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### BGP facts verification test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=bgp_fact -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set testbed

##### BGP Multipath Relax test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=bgp_multipath_relax -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set testbed
- This test only works for T1 related topologies(t1, t1-lag, ...)
- You might need to redeploy your VMs before you run this test due to the change for ToR VM router configuration changes
   `./testbed-cli.sh config-vm your-topo-name(vms1-1) your-vm-name(VM0108)` will do this for you

##### Config test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=config -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set testbed

##### Continuous Reboot test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=continuous_reboot -e testbed_name={TESTBED_NAME} -e repeat_count={REPEAT_COUNT}
```
- Requires switch connected to a VM set testbed
- Replace {REPEAT_COUNT} with the number of times the reboot has to be done. Default: 3

##### CoPP test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=copp -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### CRM test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=crm -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set testbed

##### DECAP test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=decap -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### DHCP relay test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=dhcp_relay -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### DIP SIP test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=dip_sip -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### DIR BCAST test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=dir_bcast -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### ECMP test
```
ansible-playbook test_sonic_by_tag.yml -i inventory --limit {DUT_NAME}, --become --tags ecmp --extra-vars "testbed_type={TESTBED_TYPE} vm_hosts=[DESTINATION_VMS] vm_source={SOURCE_VM} [ipv6=True]"
```
- Requires switch connected to a VM testbed (t1); default IPv4

##### ECN WRED test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=ecn_wred -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM testbed

##### Everflow_testbed test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=everflow_testbed -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### Fast reboot link util test
```
ansible-playbook -i linkstate/testbed_inv.py -e target_host={TESTBED_NAME} linkstate/{STATE}.yml
```
- Requires switch connected to a PTF testbed
- Replace {STATE} with up or down
- This test is run before running the fast-reboot/warm-reboot tests and is used to enable link state propagation from fanout to the VMS

##### FAST REBOOT test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=fast-reboot -e testbed_name={TESTBED_NAME} -e new_sonic_image={IMAGE_URL} --stay_in_target_image={VALUE1} --cleanup_old_sonic_images={VALUE2}
```
- Requires switch connected to PTF testbed
- Replace {IMAGE_URL} with the link pointing to the next image to fast-reboot into
- Replace {VALUE1} and {VALUE2} with true/false. Default: false
- stay_in_target_image parameter decides if the DUT should be reverted back to the old image after fast-reboot
- cleanup_old_sonic_images parameter will decide if all the images on the DUT should be cleaned up except for the current and the next images

##### FDB test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=fdb -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### FDB Mac expire test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=fdb_mac_expire -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### FIB v4 test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=fib -e testbed_name={TESTBED_NAME} -e ipv6=False
```
- Requires switch connected to a PTF testbed

##### FIB v6 test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=fib -e testbed_name={TESTBED_NAME} -e ipv4=False
```
- Requires switch connected to a PTF testbed

##### LAG test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=lag_2 -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set testbed with lags configured

##### Link Flap test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=link_flap -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to fanout switch. VM or PTF testbed

##### LLDP test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME},lldp_neighbors -e testcase_name=lldp -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set testbed

##### MAC read test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME} -e testbed_name={TESTBED_NAME} -e testbed_type={TESTBED_TYPE} -e testcase_name=read_mac -e iterations={ITERATIONS} -e image1={IMAGE1} -e image2={IMAGE2}
```
- Replace {ITERATIONS} with the integer number of image flipping iterations.
- Replace {IMAGE1} and {IMAGE2} with URLs to the specific SONiC binary images.
- Requires switch connected to a VM set testbed

##### Mem check test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=mem_check -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set or PTF testbed

##### MTU test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=mtu -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to PTF testbed

##### Neighbor Mac test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=neighbor -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### Neighbor Mac address change test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=neighbor_mac_noptf -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set or PTF testbed

### SNMP memory test
```
ansible-playbook test_sonic.yml -i inventory --limit {DUT_NAME}, --become --tags snmp_memory -e "tolerance=0.05" -e "min_memory_size=512000"
```

##### NTP test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=ntp -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set or PTF testbed

##### PFC watchdog test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=pfc_wd -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### Portstat test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=portstat -e testbed_name={TESTBED_NAME}
```

##### Port Toggle test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=port_toggle -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set or PTF testbed

##### Reboot test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=reboot -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set or PTF testbed

##### Sensors test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=sensors -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set or PTF testbed

##### Service ACL test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=service_acl -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set or PTF testbed

##### SNMP tests
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=snmp -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set or PTF testbed

##### Syslog test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=syslog -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a VM set or PTF testbed

##### VLAN test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=vlan -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed
- Requires switch connected to fanout switch and fanout switch need support [QinQ](https://en.wikipedia.org/wiki/IEEE_802.1ad).

##### VNET test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=vnet_vxlan -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### Vxlan decap test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=vxlan-decap -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### Warm reboot test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=warm-reboot -e testbed_name={TESTBED_NAME} -e new_sonic_image={IMAGE_URL} -e stay_in_target_image={VALUE1} -e cleanup_old_sonic_images={VALUE2}
```
- Requires switch connected to PTF testbed
- Replace {IMAGE_URL} with the link pointing to the next image to warm-reboot into
- Replace {VALUE1} and {VALUE2} with true/false. Default: false
- stay_in_target_image parameter decides if the DUT should be reverted back to the old image after warm-reboot
- cleanup_old_sonic_images parameter will decide if all the images on the DUT should be cleaned up except for the current and the next images
- parameters 'new_sonic_image', 'stay_in_target_image', 'cleanup_old_sonic_images' are optional

##### Warm reboot FIB test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=warm-reboot-fib -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed

##### Warm reboot Sad test
```
ansible-playbook test_sonic.yml -i {INVENTORY} --limit {DUT_NAME} -e testcase_name=warm-reboot-sad -e testbed_name={TESTBED_NAME}
```
- Requires switch connected to a PTF testbed
